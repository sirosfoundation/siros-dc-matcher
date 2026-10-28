"""The WebAssembly 1.0 binary format, as far as the scripts in this directory
read and write it: LEB128 integers, names, sections, value types, function
types, imports and exports.

Every read goes through `Reader`. A module that breaks the format raises
`WasmFormatError`, which names the offset of the offending byte in the module.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import TypeAlias, TypeVar

MAGIC_AND_VERSION = b"\0asm\x01\0\0\0"
FUNCTION_TYPE_FORM = 0x60

T = TypeVar("T")
E = TypeVar("E", bound=Enum)


class WasmFormatError(ValueError):
    """A module that breaks the binary format at byte `offset`."""

    def __init__(self, offset: int, message: str) -> None:
        super().__init__(f"byte {offset:#x}: {message}")
        self.offset = offset


class Reader:
    """Reads the bytes of `module` from `start` to `end`, front to back.

    Offsets count from the first byte of the module, so an error names the
    same position a hex dump of the file shows.
    """

    def __init__(self, module: bytes, start: int = 0, end: int | None = None) -> None:
        self._module = module
        self._offset = start
        self._end = len(module) if end is None else end

    @property
    def offset(self) -> int:
        return self._offset

    def at_end(self) -> bool:
        return self._offset >= self._end

    def expect_end(self, what: str) -> None:
        """Refuses bytes left over after `what`."""
        if not self.at_end():
            raise WasmFormatError(self._offset, f"{self._end - self._offset} bytes follow the {what}")

    def byte(self) -> int:
        if self.at_end():
            raise WasmFormatError(self._offset, "unexpected end")
        value = self._module[self._offset]
        self._offset += 1
        return value

    def raw(self, count: int) -> bytes:
        start = self._offset
        self.take(count)
        return self.since(start)

    def take(self, count: int) -> Reader:
        """A reader over the next `count` bytes; this reader moves past them."""
        remaining = self._end - self._offset
        if count > remaining:
            raise WasmFormatError(self._offset, f"{count} bytes needed, {remaining} remain")
        start = self._offset
        self._offset += count
        return Reader(self._module, start, self._offset)

    def since(self, start: int) -> bytes:
        """The bytes from `start` up to the current offset."""
        return self._module[start:self._offset]

    def u32(self) -> int:
        return self._leb128(32, signed=False)

    def s32(self) -> int:
        return self._leb128(32, signed=True)

    def s33(self) -> int:
        """A block type: an index or a negative value-type code."""
        return self._leb128(33, signed=True)

    def s64(self) -> int:
        return self._leb128(64, signed=True)

    def index(self, count: int, what: str) -> int:
        """An index into `count` items of `what`."""
        start = self._offset
        value = self.u32()
        if value >= count:
            raise WasmFormatError(start, f"{what} index {value}, the module has {count}")
        return value

    def name(self) -> str:
        length = self.u32()
        start = self._offset
        encoded = self.raw(length)
        try:
            return encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise WasmFormatError(start, "a name that is not UTF-8") from error

    def vector(self, read_item: Callable[[Reader], T]) -> list[T]:
        """A count, then that many items."""
        return [read_item(self) for _ in range(self.u32())]

    def enum(self, kind: type[E], what: str) -> E:
        """One byte that is the value of a member of `kind`."""
        start = self._offset
        code = self.byte()
        try:
            return kind(code)
        except ValueError as error:
            raise WasmFormatError(start, f"unknown {what} {code:#04x}") from error

    def _leb128(self, bits: int, signed: bool) -> int:
        start = self._offset
        most_bytes = (bits + 6) // 7
        result = shift = 0
        for _ in range(most_bytes):
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                break
        else:
            raise WasmFormatError(start, f"LEB128 longer than {most_bytes} bytes")
        if signed and byte & 0x40:
            result -= 1 << shift
        low, high = (-(1 << (bits - 1)), 1 << (bits - 1)) if signed else (0, 1 << bits)
        if not low <= result < high:
            raise WasmFormatError(start, f"{result} does not fit {bits} bits")
        return result


def encode_u32(value: int) -> bytes:
    """Unsigned LEB128 in the fewest bytes."""
    out = bytearray()
    while True:
        low, value = value & 0x7F, value >> 7
        if not value:
            out.append(low)
            return bytes(out)
        out.append(low | 0x80)


def encode_name(text: str) -> bytes:
    encoded = text.encode("utf-8")
    return encode_u32(len(encoded)) + encoded


def encode_vector(items: Sequence[bytes]) -> bytes:
    return encode_u32(len(items)) + b"".join(items)


class SectionId(IntEnum):
    CUSTOM = 0
    TYPE = 1
    IMPORT = 2
    FUNCTION = 3
    TABLE = 4
    MEMORY = 5
    GLOBAL = 6
    EXPORT = 7
    START = 8
    ELEMENT = 9
    CODE = 10
    DATA = 11
    DATA_COUNT = 12
    TAG = 13


# The order the sections must appear in, each at most once. Custom sections
# may appear anywhere.
SECTION_ORDER = (
    SectionId.TYPE, SectionId.IMPORT, SectionId.FUNCTION, SectionId.TABLE,
    SectionId.MEMORY, SectionId.TAG, SectionId.GLOBAL, SectionId.EXPORT,
    SectionId.START, SectionId.ELEMENT, SectionId.DATA_COUNT, SectionId.CODE,
    SectionId.DATA,
)


@dataclass(frozen=True)
class Section:
    """One section: its id and where its payload lies in the module."""

    id: SectionId
    module: bytes = field(repr=False)
    start: int
    end: int

    @property
    def payload(self) -> bytes:
        return self.module[self.start:self.end]

    def reader(self) -> Reader:
        return Reader(self.module, self.start, self.end)

    def items(self, read_item: Callable[[Reader], T]) -> list[T]:
        """The section's vector of items, which must fill the payload."""
        reader = self.reader()
        items = reader.vector(read_item)
        reader.expect_end(f"{self.id.name.lower()} section")
        return items


def encode_section(section_id: SectionId, payload: bytes) -> bytes:
    return bytes([section_id]) + encode_u32(len(payload)) + payload


def read_sections(module: bytes) -> list[Section]:
    """The sections of a module, checked against the header and the order."""
    if not module.startswith(MAGIC_AND_VERSION):
        raise WasmFormatError(0, "not a WebAssembly 1.0 module")
    reader = Reader(module, len(MAGIC_AND_VERSION))
    sections: list[Section] = []
    last_position = -1
    while not reader.at_end():
        id_offset = reader.offset
        section_id = reader.enum(SectionId, "section id")
        size = reader.u32()
        start = reader.offset
        reader.raw(size)
        if section_id is not SectionId.CUSTOM:
            position = SECTION_ORDER.index(section_id)
            if position <= last_position:
                raise WasmFormatError(id_offset, f"{section_id.name.lower()} section out of order")
            last_position = position
        sections.append(Section(section_id, module, start, reader.offset))
    return sections


class ValType(Enum):
    I32 = 0x7F
    I64 = 0x7E
    F32 = 0x7D
    F64 = 0x7C
    V128 = 0x7B
    FUNCREF = 0x70
    EXTERNREF = 0x6F

    def __str__(self) -> str:
        return self.name.lower()


def read_valtype(reader: Reader) -> ValType:
    return reader.enum(ValType, "value type")


@dataclass(frozen=True)
class Signature:
    """A function type."""

    params: tuple[ValType, ...]
    results: tuple[ValType, ...] = ()

    def __str__(self) -> str:
        """Both lists as a Python tuple of type names: `(('i32',), ())`."""
        return str((tuple(map(str, self.params)), tuple(map(str, self.results))))


def read_signature(reader: Reader) -> Signature:
    start = reader.offset
    form = reader.byte()
    if form != FUNCTION_TYPE_FORM:
        raise WasmFormatError(start, f"type form {form:#04x}, a function type is {FUNCTION_TYPE_FORM:#04x}")
    params = tuple(reader.vector(read_valtype))
    return Signature(params, tuple(reader.vector(read_valtype)))


class ExternKind(Enum):
    FUNC = 0
    TABLE = 1
    MEMORY = 2
    GLOBAL = 3
    TAG = 4

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class FunctionImport:
    module: str
    name: str
    type_index: int


@dataclass(frozen=True)
class OtherImport:
    """An imported table, memory, global or tag."""

    module: str
    name: str
    kind: ExternKind


Import: TypeAlias = FunctionImport | OtherImport


def read_limits(reader: Reader) -> None:
    """Steps over table or memory limits: a minimum, and a maximum when flagged."""
    start = reader.offset
    flags = reader.byte()
    if flags > 3:
        raise WasmFormatError(start, f"limits flags {flags:#04x}")
    reader.u32()
    if flags & 1:
        reader.u32()


class Mutability(Enum):
    CONST = 0
    VAR = 1


class TagAttribute(Enum):
    EXCEPTION = 0


def read_import(reader: Reader, type_count: int) -> Import:
    """One import; a function's type index must name one of `type_count` types."""
    module, name = reader.name(), reader.name()
    kind = reader.enum(ExternKind, "import kind")
    if kind is ExternKind.FUNC:
        return FunctionImport(module, name, reader.index(type_count, "type"))
    if kind is ExternKind.TABLE:
        read_valtype(reader)
        read_limits(reader)
    elif kind is ExternKind.MEMORY:
        read_limits(reader)
    elif kind is ExternKind.GLOBAL:
        read_valtype(reader)
        reader.enum(Mutability, "global mutability")
    else:
        reader.enum(TagAttribute, "tag attribute")
        reader.index(type_count, "type")
    return OtherImport(module, name, kind)


@dataclass(frozen=True)
class Export:
    name: str
    kind: ExternKind
    index: int


def read_export(reader: Reader, function_count: int) -> Export:
    """One export; a function's index must name one of `function_count` functions."""
    name = reader.name()
    kind = reader.enum(ExternKind, "export kind")
    if kind is ExternKind.FUNC:
        return Export(name, kind, reader.index(function_count, "function"))
    return Export(name, kind, reader.u32())


def section_items(
    sections: Sequence[Section], section_id: SectionId, read_item: Callable[[Reader], T]
) -> list[T]:
    """The items of the section with `section_id`; none when the module lacks it."""
    section = next((section for section in sections if section.id is section_id), None)
    return [] if section is None else section.items(read_item)
