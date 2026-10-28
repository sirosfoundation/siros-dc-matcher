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

The matcher is a regular `.wasm` file inside this repository. Prints the
imports and the host level the binary needs. Exits 1 on any violation and on
a module that breaks the binary format, and 2 on a refused argument.
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import ClassVar

from repo_paths import PathRefused, existing_file
from wasm_binary import (
    Export, ExternKind, FunctionImport, Import, OtherImport, SectionId, Signature, ValType,
    WasmFormatError, read_export, read_import, read_sections, read_signature, section_items,
)

I32, I64 = ValType.I32, ValType.I64
HEADER = "the header"
WASI_PREVIEW_1 = "WASI preview 1"


def fn(*params: ValType, results: tuple[ValType, ...] = ()) -> Signature:
    return Signature(params, results)


@dataclass(frozen=True)
class HostFunction:
    """A function the host provides from host `level` on, with the signature
    `source` gives it."""

    module: str
    name: str
    level: int
    signature: Signature
    source: str


def credman(module: str, name: str, level: int, signature: Signature) -> HostFunction:
    return HostFunction(module, name, level, signature, HEADER)


def wasi(name: str, signature: Signature) -> HostFunction:
    """A WASI function, which the host provides at every level."""
    return HostFunction("wasi_snapshot_preview1", name, 1, signature, WASI_PREVIEW_1)


def by_import_name(functions: Iterable[HostFunction]) -> dict[tuple[str, str], HostFunction]:
    table: dict[tuple[str, str], HostFunction] = {}
    for function in functions:
        key = (function.module, function.name)
        if key in table:
            raise ValueError(f"{function.module}.{function.name} is in the table twice")
        table[key] = function
    return table


HOST_FUNCTIONS = by_import_name([
    credman("credman", "AddEntry", 1, fn(I64, *[I32] * 6)),
    credman("credman", "AddField", 1, fn(I64, I32, I32)),
    credman("credman", "AddStringIdEntry", 1, fn(*[I32] * 7)),
    credman("credman", "AddFieldForStringIdEntry", 1, fn(*[I32] * 3)),
    credman("credman", "GetRequestBuffer", 1, fn(I32)),
    credman("credman", "GetRequestSize", 1, fn(I32)),
    credman("credman", "ReadCredentialsBuffer", 1, fn(I32, I32, I32, results=(I32,))),
    credman("credman", "GetCredentialsSize", 1, fn(I32)),
    credman("credman", "GetWasmVersion", 1, fn(I32)),
    credman("credman", "AddPaymentEntry", 1, fn(*[I32] * 11)),
    credman("credman", "AddInlineIssuanceEntry", 1, fn(*[I32] * 5)),
    credman("credman", "SetAdditionalDisclaimerAndUrlForVerificationEntry", 1, fn(*[I32] * 4)),
    credman("credman", "GetCallingAppInfo", 1, fn(I32)),
    credman("credman_v2", "AddEntrySet", 2, fn(I32, I32)),
    credman("credman_v2", "AddEntryToSet", 2, fn(*[I32] * 10)),
    credman("credman_v2", "AddFieldToEntrySet", 2, fn(*[I32] * 5)),
    credman("credman_v2", "AddPaymentEntryToSet", 2, fn(*[I32] * 14)),
    credman("credman_v2", "AddPaymentEntryToSetV2", 3, fn(*[I32] * 15)),
    credman("credman_v4", "SelfDeclarePackageInfo", 4, fn(*[I32] * 3)),
    credman("credman_v5", "AddMetadataDisplayTextToEntrySet", 5, fn(*[I32] * 4)),
    credman("credman_v6", "SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet", 6,
            fn(*[I32] * 6)),
    credman("credman_v7", "SetDelegationTypeForEntryInSet", 7, fn(*[I32] * 4)),
    wasi("fd_write", fn(I32, I32, I32, I32, results=(I32,))),
    wasi("fd_seek", fn(I32, I64, I32, I32, results=(I32,))),
    wasi("fd_close", fn(I32, results=(I32,))),
    wasi("fd_fdstat_get", fn(I32, I32, results=(I32,))),
    wasi("proc_exit", fn(I32)),
])


@dataclass(frozen=True)
class CalledFunction:
    """An export the host calls with `signature`."""

    name: str
    signature: Signature
    kind: ClassVar[ExternKind] = ExternKind.FUNC


@dataclass(frozen=True)
class AccessedMemory:
    """An export the host reads and writes."""

    name: str
    kind: ClassVar[ExternKind] = ExternKind.MEMORY


# The host calls `_start` with no arguments and reads `memory`.
REQUIRED_EXPORTS: tuple[CalledFunction | AccessedMemory, ...] = (
    CalledFunction("_start", fn()),
    AccessedMemory("memory"),
)


@dataclass(frozen=True)
class ModuleInterface:
    """A module's function types, imports and exports, and the type index of
    each function, imported ones first."""

    types: tuple[Signature, ...]
    imports: tuple[Import, ...]
    exports: tuple[Export, ...]
    function_types: tuple[int, ...]

    def export(self, name: str) -> Export | None:
        return next((export for export in self.exports if export.name == name), None)

    def signature_of(self, item: FunctionImport) -> Signature:
        return self.types[item.type_index]

    def function_signature(self, index: int) -> Signature:
        return self.types[self.function_types[index]]


def read_interface(module: bytes) -> ModuleInterface:
    sections = read_sections(module)
    types = tuple(section_items(sections, SectionId.TYPE, read_signature))
    imports = tuple(section_items(sections, SectionId.IMPORT, lambda r: read_import(r, len(types))))
    defined = section_items(sections, SectionId.FUNCTION, lambda r: r.index(len(types), "type"))
    function_types = tuple(i.type_index for i in imports if isinstance(i, FunctionImport))
    function_types += tuple(defined)
    exports = tuple(section_items(sections, SectionId.EXPORT,
                                  lambda r: read_export(r, len(function_types))))
    return ModuleInterface(types, imports, exports, function_types)


@dataclass(frozen=True)
class Report:
    """What the check prints: one line per import, the host level the imports
    need, and every violation."""

    imports: tuple[str, ...]
    level: int
    violations: tuple[str, ...]

    def show(self) -> None:
        for line in self.imports:
            print(f"  import {line}")
        print(f"  host level needed to resolve every import: {self.level}")
        for violation in self.violations:
            print(f"::error::{violation}")


def import_violation(item: Import, interface: ModuleInterface) -> str | None:
    shown = f"{item.module}.{item.name}"
    if isinstance(item, OtherImport):
        return f"{shown}: imports a {item.kind}; the host provides functions only"
    host = HOST_FUNCTIONS.get((item.module, item.name))
    if host is None:
        return f"{shown}: not in the Credential Manager ABI or the known WASI subset"
    signature = interface.signature_of(item)
    if signature != host.signature:
        return f"{shown}: signature {signature}, {host.source} gives {host.signature}"
    return None


def export_violation(required: CalledFunction | AccessedMemory, interface: ModuleInterface) -> str | None:
    export = interface.export(required.name)
    if export is None:
        return f"export {required.name} is missing"
    if export.kind is not required.kind:
        return f"export {required.name} is a {export.kind}, the host needs a {required.kind}"
    if isinstance(required, CalledFunction):
        signature = interface.function_signature(export.index)
        if signature != required.signature:
            return f"export {required.name} has signature {signature}, the host calls {required.signature}"
    return None


def import_line(item: Import, interface: ModuleInterface) -> str:
    """The import's name, then its signature, or the kind of a non-function."""
    described = interface.signature_of(item) if isinstance(item, FunctionImport) else item.kind
    return f"{item.module}.{item.name} {described}"


def level_needed(imports: Sequence[Import]) -> int:
    """The lowest host level that provides every import in the table."""
    levels = (HOST_FUNCTIONS.get((item.module, item.name)) for item in imports)
    return max((host.level for host in levels if host is not None), default=1)


def check(module: bytes) -> Report:
    interface = read_interface(module)
    violations = [import_violation(item, interface) for item in interface.imports]
    violations += [export_violation(required, interface) for required in REQUIRED_EXPORTS]
    return Report(
        imports=tuple(import_line(item, interface) for item in interface.imports),
        level=level_needed(interface.imports),
        violations=tuple(violation for violation in violations if violation is not None),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check a matcher's imports and exports against the Credential Manager ABI.")
    parser.add_argument("matcher", metavar="MATCHER.wasm",
                        help="the matcher binary, a .wasm file inside this repository")
    arguments = parser.parse_args(argv)
    try:
        path = existing_file(arguments.matcher, ".wasm")
    except PathRefused as refused:
        parser.error(str(refused))
    print(arguments.matcher)
    with path.open("rb") as matcher:
        module = matcher.read()
    try:
        report = check(module)
    except WasmFormatError as error:
        print(f"::error::{arguments.matcher}: {error}")
        return 1
    report.show()
    return 1 if report.violations else 0


if __name__ == "__main__":
    sys.exit(main())
