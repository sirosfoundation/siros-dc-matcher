#!/usr/bin/env python3
"""
Patch a wasm32-wasip1 binary to stub out the wasi_snapshot_preview1
environ_get / environ_sizes_get imports as local no-op functions.

    python3 scripts/strip_wasi_environ.py IN.wasm OUT.wasm

These two imports come from Rust's WASI command-model CRT startup
(crt1-command.o), unconditionally, regardless of user code. If the host
does not provide them, a call to either traps
(crates/android-credman-sys/ABI.md section 3) - indistinguishable, from the
outside, from "never invoked".

This rewrites:
  - the import section (drops the two entries)
  - the function + code sections (prepends two stub function bodies,
    occupying exactly the function-index slots vacated by the removed
    imports)
  - every function-index reference elsewhere (export section, start
    section, element section, and every `call`/`ref.func` instruction in
    every function body), found by decoding each instruction.

Both stubs share the same (i32,i32)->i32 signature: (errno) environ_get
writes nothing and returns 0; environ_sizes_get writes 0 to both output
pointers and returns 0 (0 env vars, 0 bytes of env data).

Both files are `.wasm` files inside this repository. Exits 1 on a module
that breaks the binary format or lacks the two imports, and 2 on a refused
argument.
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum, auto

from repo_paths import PathRefused, existing_file, new_file
from wasm_binary import (
    MAGIC_AND_VERSION, ExternKind, FunctionImport, Reader, Section, SectionId, WasmFormatError,
    encode_name, encode_section, encode_u32, encode_vector, read_export, read_import,
    read_sections, read_signature, read_valtype, section_items,
)

TARGET_MODULE = "wasi_snapshot_preview1"
TARGET_FIELDS = ("environ_get", "environ_sizes_get")


class StripError(ValueError):
    """A module this script does not rewrite."""


# ---- instructions -------------------------------------------------------

class Immediate(Enum):
    """How an instruction encodes one immediate operand."""

    U32 = auto()  # an index, a label, an alignment or an offset
    FUNCTION = auto()  # a function index, renumbered by the rewrite
    S32 = auto()
    S33 = auto()  # a block type
    S64 = auto()
    BYTE = auto()  # a reference type
    F32 = auto()
    F64 = auto()
    LABELS = auto()  # br_table's vector of labels
    VALTYPES = auto()  # select's vector of value types


U32, FUNCTION, S32, S33, S64 = Immediate.U32, Immediate.FUNCTION, Immediate.S32, Immediate.S33, Immediate.S64
BYTE, F32, F64 = Immediate.BYTE, Immediate.F32, Immediate.F64
LABELS, VALTYPES = Immediate.LABELS, Immediate.VALTYPES

# The bytes each immediate occupies, other than a function index.
STEP_OVER: dict[Immediate, Callable[[Reader], object]] = {
    U32: Reader.u32,
    S32: Reader.s32,
    S33: Reader.s33,
    S64: Reader.s64,
    BYTE: read_valtype,
    F32: lambda reader: reader.raw(4),
    F64: lambda reader: reader.raw(8),
    LABELS: lambda reader: reader.vector(Reader.u32),
    VALTYPES: lambda reader: reader.vector(read_valtype),
}


def opcodes(codes: Iterable[int], *immediates: Immediate) -> dict[int, tuple[Immediate, ...]]:
    return {code: immediates for code in codes}


OPCODES = {
    # unreachable, nop, else, end, return, drop, select, ref.is_null, then
    # the comparisons, arithmetic, conversions and sign extensions
    **opcodes([0x00, 0x01, 0x05, 0x0B, 0x0F, 0x1A, 0x1B, 0xD1, *range(0x45, 0xC5)]),
    **opcodes([0x02, 0x03, 0x04], S33),  # block, loop, if
    **opcodes([0x0C, 0x0D], U32),  # br, br_if
    0x0E: (LABELS, U32),  # br_table
    0x10: (FUNCTION,),  # call
    0x11: (U32, U32),  # call_indirect: type, table
    0x1C: (VALTYPES,),  # select t*
    **opcodes(range(0x20, 0x27), U32),  # local.get/set/tee, global.get/set, table.get/set
    **opcodes(range(0x28, 0x3F), U32, U32),  # loads and stores: alignment, offset
    **opcodes([0x3F, 0x40], U32),  # memory.size, memory.grow
    0x41: (S32,),  # i32.const
    0x42: (S64,),  # i64.const
    0x43: (F32,),  # f32.const
    0x44: (F64,),  # f64.const
    0xD0: (BYTE,),  # ref.null
    0xD2: (FUNCTION,),  # ref.func
}

PREFIX_FC = 0xFC
FC_OPCODES = {
    **opcodes(range(0x00, 0x08)),  # trunc_sat
    **opcodes([0x08, 0x0A, 0x0C, 0x0E], U32, U32),  # memory.init/copy, table.init/copy
    **opcodes([0x09, 0x0B, 0x0D, 0x0F, 0x10, 0x11], U32),  # data.drop, memory.fill, elem.drop, table.grow/size/fill
}

END = 0x0B
# The opcodes a constant expression may hold, its final `end` aside.
CONSTANT_OPCODES = {0x41, 0x42, 0x43, 0x44, 0x23, 0xD0, 0xD2}


@dataclass(frozen=True)
class Renumbering:
    """The function indices after the rewrite. The two removed imports, at
    `removed` in ascending order, become the first two defined functions; the
    imports after them move down."""

    imported: int  # function imports before the rewrite
    removed: tuple[int, int]

    def __call__(self, index: int) -> int:
        if index in self.removed:
            return self.imported - 2 + self.removed.index(index)
        if index < self.imported:
            return index - sum(1 for gone in self.removed if gone < index)
        return index


def immediates_of(reader: Reader, opcode: int, start: int) -> tuple[Immediate, ...]:
    """The immediates of the instruction `opcode` starts, reading a 0xFC sub-opcode."""
    if opcode == PREFIX_FC:
        sub_start = reader.offset
        sub = reader.u32()
        if sub not in FC_OPCODES:
            raise WasmFormatError(sub_start, f"unhandled 0xfc sub-opcode {sub:#x}")
        return FC_OPCODES[sub]
    if opcode not in OPCODES:
        raise WasmFormatError(start, f"unhandled opcode {opcode:#04x}")
    return OPCODES[opcode]


def copy_instruction(reader: Reader, renumber: Renumbering, out: bytearray) -> int:
    """Copies one instruction into `out`, renumbering its function index.
    Returns its opcode."""
    start = reader.offset
    opcode = reader.byte()
    immediates = immediates_of(reader, opcode, start)
    out += reader.since(start)
    for immediate in immediates:
        if immediate is FUNCTION:
            out += encode_u32(renumber(reader.u32()))
        else:
            operand_start = reader.offset
            STEP_OVER[immediate](reader)
            out += reader.since(operand_start)
    return opcode


def rewrite_expression(reader: Reader, renumber: Renumbering) -> bytes:
    """Every instruction up to the end of `reader`."""
    out = bytearray()
    while not reader.at_end():
        copy_instruction(reader, renumber, out)
    return bytes(out)


def rewrite_constant_expression(reader: Reader, renumber: Renumbering) -> bytes:
    """A constant expression, up to and including its `end`."""
    out = bytearray()
    while True:
        start = reader.offset
        opcode = copy_instruction(reader, renumber, out)
        if opcode == END:
            return bytes(out)
        if opcode not in CONSTANT_OPCODES:
            raise WasmFormatError(start, f"opcode {opcode:#04x} in a constant expression")


# ---- sections -----------------------------------------------------------

@dataclass(frozen=True)
class RemovedImport:
    index: int  # its function index
    name: str


@dataclass(frozen=True)
class ImportRewrite:
    """The import section without the two imports, and what they were."""

    payload: bytes
    imported: int  # function imports before the rewrite
    removed: tuple[RemovedImport, RemovedImport]  # by function index
    stub_type: int  # the type index both share


def is_target(item: FunctionImport) -> bool:
    return item.module == TARGET_MODULE and item.name in TARGET_FIELDS


def rewrite_imports(section: Section, type_count: int) -> ImportRewrite:
    reader = section.reader()
    kept: list[bytes] = []
    removed: list[tuple[RemovedImport, int]] = []
    imported = 0
    for _ in range(reader.u32()):
        start = reader.offset
        item = read_import(reader, type_count)
        if isinstance(item, FunctionImport) and is_target(item):
            removed.append((RemovedImport(imported, item.name), item.type_index))
        else:
            kept.append(reader.since(start))
        if isinstance(item, FunctionImport):
            imported += 1
    reader.expect_end("import section")
    if len(removed) != 2:
        wanted = " and ".join(f"{TARGET_MODULE}.{name}" for name in TARGET_FIELDS)
        raise StripError(f"expected the imports {wanted}, found {len(removed)} of them")
    (first, first_type), (second, second_type) = removed
    if first_type != second_type:
        raise StripError("expected both imports to share one type index")
    return ImportRewrite(encode_vector(kept), imported, (first, second), first_type)


def stub_body(name: str) -> bytes:
    """A hand-encoded (i32,i32)->i32 no-op body: no locals, then the expression."""
    expressions = {
        "environ_sizes_get": bytes([
            0x20, 0x00,        # local.get 0
            0x41, 0x00,        # i32.const 0
            0x36, 0x02, 0x00,  # i32.store align=2 offset=0
            0x20, 0x01,        # local.get 1
            0x41, 0x00,        # i32.const 0
            0x36, 0x02, 0x00,  # i32.store align=2 offset=0
            0x41, 0x00,        # i32.const 0   (return value: errno 0)
            0x0B,              # end
        ]),
        "environ_get": bytes([
            0x41, 0x00,  # i32.const 0  (return value: errno 0)
            0x0B,        # end
        ]),
    }
    body = encode_u32(0) + expressions[name]
    return encode_u32(len(body)) + body


def read_local_group(reader: Reader) -> None:
    reader.u32()
    read_valtype(reader)


def renumber_body(reader: Reader, renumber: Renumbering) -> bytes:
    body = reader.take(reader.u32())
    locals_start = body.offset
    body.vector(read_local_group)
    rewritten = body.since(locals_start) + rewrite_expression(body, renumber)
    return encode_u32(len(rewritten)) + rewritten


def renumber_element_segment(reader: Reader, renumber: Renumbering) -> bytes:
    start = reader.offset
    flags = reader.u32()
    if flags != 0:
        raise WasmFormatError(start, f"element segment flags {flags}; only 0 is handled")
    offset = rewrite_constant_expression(reader, renumber)
    functions = reader.vector(Reader.u32)
    return encode_u32(flags) + offset + encode_vector([encode_u32(renumber(f)) for f in functions])


@dataclass(frozen=True)
class Rewrite:
    """What every section rewrite shares."""

    imports: ImportRewrite
    renumber: Renumbering
    type_count: int
    function_count: int

    def payload(self, section: Section) -> bytes:
        match section.id:
            case SectionId.IMPORT:
                return self.imports.payload
            case SectionId.FUNCTION:
                return self.function_section(section)
            case SectionId.EXPORT:
                return self.export_section(section)
            case SectionId.START:
                return self.start_section(section)
            case SectionId.ELEMENT:
                return self.element_section(section)
            case SectionId.CODE:
                return self.code_section(section)
            case _:
                return section.payload

    def function_section(self, section: Section) -> bytes:
        """The stubs' type twice, ahead of the defined functions' types."""
        reader = section.reader()
        count = reader.u32()
        types_start = reader.offset
        for _ in range(count):
            reader.index(self.type_count, "type")
        reader.expect_end("function section")
        stubs = encode_u32(self.imports.stub_type) * 2
        return encode_u32(count + 2) + stubs + reader.since(types_start)

    def export_section(self, section: Section) -> bytes:
        exports = section.items(lambda reader: read_export(reader, self.function_count))
        return encode_vector([
            encode_name(export.name) + bytes([export.kind.value])
            + encode_u32(self.renumber(export.index) if export.kind is ExternKind.FUNC else export.index)
            for export in exports
        ])

    def start_section(self, section: Section) -> bytes:
        reader = section.reader()
        start = reader.index(self.function_count, "function")
        reader.expect_end("start section")
        return encode_u32(self.renumber(start))

    def element_section(self, section: Section) -> bytes:
        return encode_vector(section.items(lambda reader: renumber_element_segment(reader, self.renumber)))

    def code_section(self, section: Section) -> bytes:
        stubs = [stub_body(removed.name) for removed in self.imports.removed]
        return encode_vector(stubs + section.items(lambda reader: renumber_body(reader, self.renumber)))


def section_with(sections: Sequence[Section], section_id: SectionId) -> Section:
    found = next((section for section in sections if section.id is section_id), None)
    if found is None:
        raise StripError(f"the module has no {section_id.name.lower()} section")
    return found


def plan_rewrite(sections: Sequence[Section]) -> Rewrite:
    type_count = len(section_items(sections, SectionId.TYPE, read_signature))
    imports = rewrite_imports(section_with(sections, SectionId.IMPORT), type_count)
    defined = section_with(sections, SectionId.FUNCTION).reader().u32()
    low, high = (removed.index for removed in imports.removed)
    return Rewrite(imports, Renumbering(imports.imported, (low, high)), type_count,
                   imports.imported + defined)


def strip(module: bytes) -> tuple[bytes, Rewrite]:
    """The module with both imports replaced by stubs, and the rewrite that made it."""
    sections = read_sections(module)
    rewrite = plan_rewrite(sections)
    rewritten = b"".join(encode_section(s.id, rewrite.payload(s)) for s in sections)
    return MAGIC_AND_VERSION + rewritten, rewrite


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replace the environ_get and environ_sizes_get imports of a wasm32-wasip1 "
                    "binary with local no-op functions.")
    parser.add_argument("source", metavar="IN.wasm", help="a .wasm file inside this repository")
    parser.add_argument("target", metavar="OUT.wasm",
                        help="the .wasm file to write, inside this repository")
    arguments = parser.parse_args(argv)
    try:
        source = existing_file(arguments.source, ".wasm")
        target = new_file(arguments.target, ".wasm")
    except PathRefused as refused:
        parser.error(str(refused))
    with source.open("rb") as file:
        module = file.read()
    try:
        stripped, rewrite = strip(module)
    except (WasmFormatError, StripError) as error:
        print(f"{arguments.source}: {error}", file=sys.stderr)
        return 1
    imported = rewrite.imports.imported
    low, high = rewrite.renumber.removed
    print(f"removing imports at old func idx {low},{high}; "
          f"stubs land at new idx {imported - 2},{imported - 1}")
    with target.open("wb") as file:
        file.write(stripped)
    print(f"wrote {arguments.target}: {len(stripped)} bytes (was {len(module)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
