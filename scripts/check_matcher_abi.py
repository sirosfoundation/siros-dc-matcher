#!/usr/bin/env python3
"""Check a matcher's imports and exports against the Credential Manager ABI.

    python3 scripts/check_matcher_abi.py target/wasm32-wasip1/wasm-release/matcher.wasm

Every function import must be in the table below with exactly its WebAssembly
signature; every export the host calls must be there. The table is written
from Google's reference header, digitalcredentialsdev/CMWallet
matcher/credentialmanager.h at abcf38a3, with the wasm32 C ABI: pointers,
size_t, int and uint32_t* are i32, long long is i64. It is kept apart from
the Rust declarations in crates/android-credman-sys on purpose, so that a
mistake in either shows up as a disagreement. crates/android-credman-sys/ABI.md
documents each row.

The WASI functions are the five that Google's own shipped matchers import
(CMWallet app/src/main/assets/*.wasm at abcf38a3) and that docs/abi.md lists
from a shipping binary. The host links a module that imports something else,
and traps when the matcher calls it: releases v0.8.0 to v0.11.0 imported
`random_get`, which the host lacks, and trapped on a zkp_req request that
reached the planner. Any import outside these tables, the `environ_*` pair
included, fails the check.

Prints the imports, the host level the binary needs, and exits 1 on any
violation.
"""
import sys

I32, I64 = "i32", "i64"


def fn(*params, result=()):
    return (tuple(params), tuple(result))


# (module, name) -> (minimum host level, (params, results))
CREDMAN = {
    ("credman", "AddEntry"): (1, fn(I64, *[I32] * 6)),
    ("credman", "AddField"): (1, fn(I64, I32, I32)),
    ("credman", "AddStringIdEntry"): (1, fn(*[I32] * 7)),
    ("credman", "AddFieldForStringIdEntry"): (1, fn(*[I32] * 3)),
    ("credman", "GetRequestBuffer"): (1, fn(I32)),
    ("credman", "GetRequestSize"): (1, fn(I32)),
    ("credman", "ReadCredentialsBuffer"): (1, fn(I32, I32, I32, result=[I32])),
    ("credman", "GetCredentialsSize"): (1, fn(I32)),
    ("credman", "GetWasmVersion"): (1, fn(I32)),
    ("credman", "AddPaymentEntry"): (1, fn(*[I32] * 11)),
    ("credman", "AddInlineIssuanceEntry"): (1, fn(*[I32] * 5)),
    ("credman", "SetAdditionalDisclaimerAndUrlForVerificationEntry"): (1, fn(*[I32] * 4)),
    ("credman", "GetCallingAppInfo"): (1, fn(I32)),
    ("credman_v2", "AddEntrySet"): (2, fn(I32, I32)),
    ("credman_v2", "AddEntryToSet"): (2, fn(*[I32] * 10)),
    ("credman_v2", "AddFieldToEntrySet"): (2, fn(*[I32] * 5)),
    ("credman_v2", "AddPaymentEntryToSet"): (2, fn(*[I32] * 14)),
    ("credman_v2", "AddPaymentEntryToSetV2"): (3, fn(*[I32] * 15)),
    ("credman_v4", "SelfDeclarePackageInfo"): (4, fn(*[I32] * 3)),
    ("credman_v5", "AddMetadataDisplayTextToEntrySet"): (5, fn(*[I32] * 4)),
    ("credman_v6", "SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet"): (
        6,
        fn(*[I32] * 6),
    ),
    ("credman_v7", "SetDelegationTypeForEntryInSet"): (7, fn(*[I32] * 4)),
}

WASI = {
    ("wasi_snapshot_preview1", "fd_write"): fn(I32, I32, I32, I32, result=[I32]),
    ("wasi_snapshot_preview1", "fd_seek"): fn(I32, I64, I32, I32, result=[I32]),
    ("wasi_snapshot_preview1", "fd_close"): fn(I32, result=[I32]),
    ("wasi_snapshot_preview1", "fd_fdstat_get"): fn(I32, I32, result=[I32]),
    ("wasi_snapshot_preview1", "proc_exit"): fn(I32),
}

# The host calls `_start` with no arguments and reads `memory`.
REQUIRED_EXPORTS = {"_start": ("func", fn()), "memory": ("memory", None)}

VALTYPES = {0x7F: I32, 0x7E: I64, 0x7D: "f32", 0x7C: "f64", 0x7B: "v128", 0x70: "funcref", 0x6F: "externref"}
EXTERN_KINDS = {0: "func", 1: "table", 2: "memory", 3: "global", 4: "tag"}


class Reader:
    def __init__(self, data, pos=0, end=None):
        self.data, self.pos, self.end = data, pos, len(data) if end is None else end

    def byte(self):
        if self.pos >= self.end:
            raise ValueError("unexpected end of section")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def uleb(self):
        result = shift = 0
        while True:
            b = self.byte()
            result |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                return result

    def bytes(self, n):
        if self.pos + n > self.end:
            raise ValueError("unexpected end of section")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def name(self):
        return self.bytes(self.uleb()).decode("utf-8")

    def valtypes(self):
        out = []
        for _ in range(self.uleb()):
            b = self.byte()
            if b not in VALTYPES:
                raise ValueError(f"unknown value type 0x{b:02x}")
            out.append(VALTYPES[b])
        return tuple(out)


def sections(data):
    if data[:8] != b"\0asm\x01\0\0\0":
        raise ValueError("not a WebAssembly 1.0 module")
    r = Reader(data, 8)
    while r.pos < len(data):
        section_id = r.byte()
        size = r.uleb()
        yield section_id, Reader(data, r.pos, r.pos + size)
        r.pos += size


def skip_limits(r):
    flags = r.byte()
    r.uleb()
    if flags & 1:
        r.uleb()


def skip_descriptor(r, kind):
    """Steps over the descriptor of a non-function import."""
    if kind == 1:
        r.byte()
        skip_limits(r)
    elif kind == 2:
        skip_limits(r)
    elif kind == 3:
        r.byte()
        r.byte()
    elif kind == 4:
        r.byte()
        r.uleb()
    else:
        raise ValueError(f"unknown import kind {kind}")


def parse(data):
    """Function types, imports and exports of a module."""
    types, imports, exports, functions = [], [], {}, []
    imported_functions = 0
    for section_id, r in sections(data):
        if section_id == 1:
            for _ in range(r.uleb()):
                if r.byte() != 0x60:
                    raise ValueError("unexpected type form")
                types.append((r.valtypes(), r.valtypes()))
        elif section_id == 2:
            for _ in range(r.uleb()):
                module, name, kind = r.name(), r.name(), r.byte()
                if kind == 0:
                    imports.append((module, name, "func", types[r.uleb()]))
                    imported_functions += 1
                else:
                    skip_descriptor(r, kind)
                    imports.append((module, name, EXTERN_KINDS.get(kind, str(kind)), None))
        elif section_id == 3:
            functions = [r.uleb() for _ in range(r.uleb())]
        elif section_id == 7:
            for _ in range(r.uleb()):
                name, kind, index = r.name(), r.byte(), r.uleb()
                exports[name] = (EXTERN_KINDS.get(kind, str(kind)), index)
    return types, imports, exports, functions, imported_functions


def check(path):
    data = open(path, "rb").read()
    types, imports, exports, functions, imported_functions = parse(data)
    errors, level = [], 1
    for module, name, kind, signature in imports:
        key = (module, name)
        shown = f"{module}.{name}"
        if kind != "func":
            errors.append(f"{shown}: imports a {kind}; the host provides functions only")
        elif key in CREDMAN:
            needed, expected = CREDMAN[key]
            if signature != expected:
                errors.append(f"{shown}: signature {signature}, the header gives {expected}")
            level = max(level, needed)
        elif key in WASI:
            if signature != WASI[key]:
                errors.append(f"{shown}: signature {signature}, WASI preview 1 gives {WASI[key]}")
        else:
            errors.append(f"{shown}: not in the Credential Manager ABI or the known WASI subset")
        print(f"  import {shown} {signature}")
    for name, (kind, expected) in REQUIRED_EXPORTS.items():
        if name not in exports:
            errors.append(f"export {name} is missing")
            continue
        got_kind, index = exports[name]
        if got_kind != kind:
            errors.append(f"export {name} is a {got_kind}, the host needs a {kind}")
        elif kind == "func":
            local = index - imported_functions
            signature = types[functions[local]] if 0 <= local < len(functions) else None
            if signature != expected:
                errors.append(f"export {name} has signature {signature}, the host calls {expected}")
    print(f"  host level needed to resolve every import: {level}")
    return errors


def main(argv):
    if len(argv) != 2:
        sys.exit(f"usage: {argv[0]} MATCHER.wasm")
    print(argv[1])
    errors = check(argv[1])
    for error in errors:
        print(f"::error::{error}")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main(sys.argv)
