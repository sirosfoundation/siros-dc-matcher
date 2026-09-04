#!/usr/bin/env python3
"""
Patch a wasm32-wasip1 binary to stub out the wasi_snapshot_preview1
environ_get / environ_sizes_get imports as local no-op functions.

These two imports come from Rust's WASI command-model CRT startup
(crt1-command.o), unconditionally, regardless of user code. If the host
does not provide them, the module fails to instantiate at all -
indistinguishable, from the outside, from "never invoked".

This rewrites:
  - the import section (drops the two entries)
  - the function + code sections (prepends two stub function bodies,
    occupying exactly the function-index slots vacated by the removed
    imports)
  - every function-index reference elsewhere (export section, start
    section, element section, and every `call`/`ref.func` instruction in
    every function body) via a byte-exact instruction walk - not a blind
    byte search.

Both stubs share the same (i32,i32)->i32 signature: (errno) environ_get
writes nothing and returns 0; environ_sizes_get writes 0 to both output
pointers and returns 0 (0 env vars, 0 bytes of env data).
"""
import sys

TARGET_MODULE = "wasi_snapshot_preview1"
TARGET_FIELDS = ("environ_get", "environ_sizes_get")


def check(cond, message):
    """Input validation that survives `python -O`. `assert` is stripped under
    optimisation, and a patcher that then carries on with a malformed module
    would write a corrupt binary without a word - the one failure mode this
    whole script exists to avoid."""
    if not cond:
        raise ValueError(message)


def read_uleb128(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if b & 0x80 == 0:
            return result, off
        shift += 7


def read_sleb128(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if b & 0x80 == 0:
            if shift < 64 and (b & 0x40):
                result |= -(1 << shift)
            return result, off


def uleb128(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_name(buf, off):
    n, off = read_uleb128(buf, off)
    s = buf[off:off + n].decode("utf-8")
    return s, off + n


def name_bytes(s):
    b = s.encode("utf-8")
    return uleb128(len(b)) + b


def split_sections(data):
    off = 8
    secs = []
    while off < len(data):
        sec_id = data[off]
        start = off
        off += 1
        size, off = read_uleb128(data, off)
        payload_start = off
        secs.append({"id": sec_id, "start": start, "payload_start": payload_start,
                     "payload": data[payload_start:payload_start + size]})
        off += size
    return secs


def encode_section(sec_id, payload):
    return bytes([sec_id]) + uleb128(len(payload)) + payload


# ---- instruction walker -----------------------------------------------
# Opcode -> immediate-decoding rule. Every entry consumes exactly the
# right number of bytes for that opcode's immediates (not its operand
# stack effects, which we don't need). `call` and `ref.func` are the only
# two that carry a function index we must remap.

NOARG = set(
    [0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B, 0xD1]
    + list(range(0x45, 0x50))  # i32 comparisons
    + list(range(0x50, 0x5B))  # i64 comparisons
    + list(range(0x5B, 0x61))  # f32 comparisons
    + list(range(0x61, 0x67))  # f64 comparisons
    + list(range(0x67, 0x79))  # i32 unop/binop
    + list(range(0x79, 0x8B))  # i64 unop/binop
    + list(range(0x8B, 0x99))  # f32 unop/binop
    + list(range(0x99, 0xA7))  # f64 unop/binop
    + list(range(0xA7, 0xC0))  # conversions
    + list(range(0xC0, 0xC5))  # sign extension
)

MEMARG_OPS = set(range(0x28, 0x3F))  # i32.load .. i64.store32


def walk_and_remap(code, remap):
    """Walk one function body's instruction stream, remapping every
    call/ref.func operand via `remap`. Returns the rewritten bytes.
    Raises on any opcode this walker doesn't recognise, rather than
    silently miscounting."""
    out = bytearray()
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        out.append(op)
        i += 1
        if op in NOARG:
            continue
        if op in (0x02, 0x03, 0x04):  # block/loop/if: blocktype (sleb33)
            start = i
            _, i = read_sleb128(code, i)
            out += code[start:i]
        elif op == 0x0C or op == 0x0D:  # br / br_if: labelidx
            start = i
            _, i = read_uleb128(code, i)
            out += code[start:i]
        elif op == 0x0E:  # br_table: vec(labelidx) + labelidx
            start = i
            count, i = read_uleb128(code, i)
            for _ in range(count):
                _, i = read_uleb128(code, i)
            _, i = read_uleb128(code, i)
            out += code[start:i]
        elif op == 0x10:  # call: funcidx -- REMAP
            idx, i = read_uleb128(code, i)
            out += uleb128(remap(idx))
        elif op == 0x11:  # call_indirect: typeidx, tableidx
            start = i
            _, i = read_uleb128(code, i)
            _, i = read_uleb128(code, i)
            out += code[start:i]
        elif op == 0x1C:  # select t*: vec(valtype byte)
            start = i
            count, i = read_uleb128(code, i)
            i += count
            out += code[start:i]
        elif op in (0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26):
            # local.get/set/tee, global.get/set, table.get/set: 1 idx
            start = i
            _, i = read_uleb128(code, i)
            out += code[start:i]
        elif op in MEMARG_OPS:  # loads/stores: align + offset
            start = i
            _, i = read_uleb128(code, i)
            _, i = read_uleb128(code, i)
            out += code[start:i]
        elif op in (0x3F, 0x40):  # memory.size / memory.grow: reserved byte
            start = i
            _, i = read_uleb128(code, i)
            out += code[start:i]
        elif op == 0x41:  # i32.const: sleb32
            start = i
            _, i = read_sleb128(code, i)
            out += code[start:i]
        elif op == 0x42:  # i64.const: sleb64
            start = i
            _, i = read_sleb128(code, i)
            out += code[start:i]
        elif op == 0x43:  # f32.const: 4 raw bytes
            out += code[i:i + 4]
            i += 4
        elif op == 0x44:  # f64.const: 8 raw bytes
            out += code[i:i + 8]
            i += 8
        elif op == 0xD0:  # ref.null: reftype byte
            out.append(code[i])
            i += 1
        elif op == 0xD2:  # ref.func: funcidx -- REMAP
            idx, i = read_uleb128(code, i)
            out += uleb128(remap(idx))
        elif op == 0xFC:  # bulk-memory / sat-trunc secondary opcode
            sub, i2 = read_uleb128(code, i)
            start = i
            i = i2
            out += code[start:i]
            if sub in (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07):
                pass  # trunc_sat: no immediates
            elif sub == 0x08:  # memory.init: dataidx, memidx
                start = i
                _, i = read_uleb128(code, i)
                _, i = read_uleb128(code, i)
                out += code[start:i]
            elif sub == 0x09:  # data.drop: dataidx
                start = i
                _, i = read_uleb128(code, i)
                out += code[start:i]
            elif sub == 0x0A:  # memory.copy: memidx, memidx
                start = i
                _, i = read_uleb128(code, i)
                _, i = read_uleb128(code, i)
                out += code[start:i]
            elif sub == 0x0B:  # memory.fill: memidx
                start = i
                _, i = read_uleb128(code, i)
                out += code[start:i]
            elif sub == 0x0C:  # table.init: elemidx, tableidx
                start = i
                _, i = read_uleb128(code, i)
                _, i = read_uleb128(code, i)
                out += code[start:i]
            elif sub == 0x0D:  # elem.drop: elemidx
                start = i
                _, i = read_uleb128(code, i)
                out += code[start:i]
            elif sub == 0x0E:  # table.copy: tableidx, tableidx
                start = i
                _, i = read_uleb128(code, i)
                _, i = read_uleb128(code, i)
                out += code[start:i]
            elif sub in (0x0F, 0x10, 0x11):  # table.grow/size/fill: tableidx
                start = i
                _, i = read_uleb128(code, i)
                out += code[start:i]
            else:
                raise ValueError(f"unhandled 0xFC sub-opcode {sub:#x} at {start:#x}")
        else:
            raise ValueError(f"unhandled opcode {op:#x} at byte {i-1:#x}")
    return bytes(out)


# ---- section-specific rewriting ---------------------------------------

def rewrite_import_section(payload, target_module, target_fields):
    count, p = read_uleb128(payload, 0)
    kept = []
    removed_func_indices = []
    func_idx = 0
    for _ in range(count):
        entry_start = p
        mod, p = read_name(payload, p)
        field, p = read_name(payload, p)
        kind = payload[p]
        p += 1
        if kind == 0:
            type_idx, p = read_uleb128(payload, p)
            is_target = mod == target_module and field in target_fields
            if is_target:
                removed_func_indices.append((func_idx, type_idx, field))
            else:
                kept.append(payload[entry_start:p])
            func_idx += 1
        elif kind == 1:
            p += 1
            flag = payload[p]
            p += 1
            _, p = read_uleb128(payload, p)
            if flag == 1:
                _, p = read_uleb128(payload, p)
            kept.append(payload[entry_start:p])
        elif kind == 2:
            flag = payload[p]
            p += 1
            _, p = read_uleb128(payload, p)
            if flag == 1:
                _, p = read_uleb128(payload, p)
            kept.append(payload[entry_start:p])
        elif kind == 3:
            p += 2
            kept.append(payload[entry_start:p])
        else:
            raise ValueError(f"unknown import kind {kind}")
    check(p == len(payload), "import section not fully consumed")
    new_payload = uleb128(len(kept)) + b"".join(kept)
    return new_payload, func_idx, removed_func_indices


def make_remap(total_imported_funcs_old, removed):
    removed_sorted = sorted(idx for idx, _, _ in removed)
    check(len(removed_sorted) == 2, f"expected 2 removed imports, got {len(removed_sorted)}")
    idx_low, idx_high = removed_sorted
    new_base = total_imported_funcs_old - 2

    def remap(old_index):
        if old_index == idx_low:
            return new_base
        if old_index == idx_high:
            return new_base + 1
        if old_index < total_imported_funcs_old:
            shift = (1 if idx_low < old_index else 0) + (1 if idx_high < old_index else 0)
            return old_index - shift
        return old_index

    return remap, idx_low, idx_high


def stub_body(kind):
    """Hand-encoded (i32,i32)->i32 no-op body bytes (locals decl + expr + end)."""
    if kind == "environ_sizes_get":
        expr = bytes([
            0x20, 0x00,        # local.get 0
            0x41, 0x00,        # i32.const 0
            0x36, 0x02, 0x00,  # i32.store align=2 offset=0
            0x20, 0x01,        # local.get 1
            0x41, 0x00,        # i32.const 0
            0x36, 0x02, 0x00,  # i32.store align=2 offset=0
            0x41, 0x00,        # i32.const 0   (return value: errno 0)
            0x0B,              # end
        ])
    elif kind == "environ_get":
        expr = bytes([
            0x41, 0x00,  # i32.const 0  (return value: errno 0)
            0x0B,        # end
        ])
    else:
        raise ValueError(kind)
    body = uleb128(0) + expr  # 0 local-declaration groups
    return uleb128(len(body)) + body


def rewrite_function_section(payload, stub_type_idx):
    count, p = read_uleb128(payload, 0)
    rest = payload[p:]
    new_count = count + 2
    prefix = uleb128(stub_type_idx) + uleb128(stub_type_idx)
    return uleb128(new_count) + prefix + rest


def rewrite_code_section(payload, remap, removed_order):
    count, p = read_uleb128(payload, 0)
    bodies = []
    for _ in range(count):
        size, p2 = read_uleb128(payload, p)
        body = payload[p2:p2 + size]
        bodies.append(body)
        p = p2 + size
    check(p == len(payload), "code section not fully consumed")

    new_bodies = []
    for _, _, field in removed_order:
        new_bodies.append(stub_body(field))

    for body in bodies:
        nlocals, q = read_uleb128(body, 0)
        head = body[:q]
        for _ in range(nlocals):
            _, q2 = read_uleb128(body, q)
            q2 += 1  # valtype byte
            head = body[:q2]
            q = q2
        expr = body[q:]
        new_expr = walk_and_remap(expr, remap)
        new_body = head + new_expr
        new_bodies.append(uleb128(len(new_body)) + new_body)

    return uleb128(len(new_bodies)) + b"".join(new_bodies)


def rewrite_export_section(payload, remap):
    count, p = read_uleb128(payload, 0)
    out = bytearray(uleb128(count))
    for _ in range(count):
        name, p = read_name(payload, p)
        kind = payload[p]
        p += 1
        idx, p = read_uleb128(payload, p)
        out += name_bytes(name)
        out.append(kind)
        if kind == 0:
            out += uleb128(remap(idx))
        else:
            out += uleb128(idx)
    return bytes(out)


def rewrite_start_section(payload, remap):
    """The start section (id 8) is a single funcidx - the function the host
    runs at instantiation. wasi-libc's command model exports `_start` rather
    than using this section, so the shipped build has none; but an input that
    does have one would otherwise run the wrong function after the shift."""
    idx, p = read_uleb128(payload, 0)
    check(p == len(payload), "start section not fully consumed")
    return uleb128(remap(idx))


def const_expr_end(buf, off):
    """Return the offset just past the `end` of the constant expression
    starting at `off`. Walked instruction by instruction, never by scanning
    for an 0x0B byte: that byte is a perfectly good LEB payload (`i32.const
    11` is `41 0B`), and stopping there would truncate the expression and
    desync everything after it. The spec limits const exprs to these
    opcodes, so anything else is a malformed module, not a gap to paper
    over."""
    while True:
        op = buf[off]
        off += 1
        if op == 0x0B:  # end
            return off
        if op in (0x41, 0x42):  # i32.const / i64.const: sleb
            _, off = read_sleb128(buf, off)
        elif op == 0x43:  # f32.const
            off += 4
        elif op == 0x44:  # f64.const
            off += 8
        elif op in (0x23, 0xD2):  # global.get globalidx / ref.func funcidx
            _, off = read_uleb128(buf, off)
        elif op == 0xD0:  # ref.null: reftype byte
            off += 1
        else:
            raise ValueError(f"unexpected opcode {op:#x} in const expr at {off-1:#x}")


def rewrite_element_section(payload, remap):
    count, p = read_uleb128(payload, 0)
    out = bytearray(uleb128(count))
    for _ in range(count):
        flags, p = read_uleb128(payload, p)
        if flags != 0:
            raise ValueError(f"unhandled element segment flags={flags}")
        out += uleb128(flags)
        start = p
        p = const_expr_end(payload, p)
        # The offset expr is an i32 const expr in practice, but a `ref.func`
        # in it would carry a funcidx too, and walk_and_remap already knows
        # every opcode a const expr may hold - so run it through the same
        # walker rather than copying verbatim.
        out += walk_and_remap(payload[start:p], remap)
        n, p = read_uleb128(payload, p)
        out += uleb128(n)
        for _ in range(n):
            idx, p = read_uleb128(payload, p)
            out += uleb128(remap(idx))
    check(p == len(payload), "element section not fully consumed")
    return bytes(out)


def main(in_path, out_path):
    data = open(in_path, "rb").read()
    check(data[:4] == b"\0asm", f"{in_path}: not a wasm module (bad magic)")
    secs = split_sections(data)

    import_sec = next(s for s in secs if s["id"] == 2)
    new_import_payload, total_imported_funcs_old, removed = rewrite_import_section(
        import_sec["payload"], TARGET_MODULE, TARGET_FIELDS)
    check(len(removed) == 2, f"expected 2 targets, found {len(removed)}")
    type_idxs = {t for _, t, _ in removed}
    check(len(type_idxs) == 1, "expected both targets to share one type index")
    stub_type_idx = type_idxs.pop()

    removed_order = sorted(removed, key=lambda t: t[0])
    remap, idx_low, idx_high = make_remap(total_imported_funcs_old, removed)
    print(f"removing imports at old func idx {idx_low},{idx_high}; "
          f"stubs land at new idx {total_imported_funcs_old-2},{total_imported_funcs_old-1}")

    out_sections = []
    for s in secs:
        sid = s["id"]
        payload = s["payload"]
        if sid == 2:
            payload = new_import_payload
        elif sid == 3:
            payload = rewrite_function_section(payload, stub_type_idx)
        elif sid == 7:
            payload = rewrite_export_section(payload, remap)
        elif sid == 8:
            payload = rewrite_start_section(payload, remap)
        elif sid == 9:
            payload = rewrite_element_section(payload, remap)
        elif sid == 10:
            payload = rewrite_code_section(payload, remap, removed_order)
        out_sections.append(encode_section(sid, payload))

    out_data = b"\0asm" + (1).to_bytes(4, "little") + b"".join(out_sections)
    open(out_path, "wb").write(out_data)
    print(f"wrote {out_path}: {len(out_data)} bytes (was {len(data)})")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
