# The Credential Manager matcher ABI

Read off the import and export tables of a shipping matcher binary, and
confirmed by building our own and diffing the resulting tables. These are
interoperability facts, not borrowed code — see
[CONTRIBUTING.md](../CONTRIBUTING.md#provenance).

## Imports

| Function | Module | Purpose |
|---|---|---|
| `GetCallingAppInfo` | `credman` | Writes `{package_name[256], origin[512]}` into guest memory — the platform-verified caller |
| `GetRequestSize` / `GetRequestBuffer` | `credman` | The DC API request JSON, shaped `{"requests":[{"protocol":…,"data":…}]}` |
| `GetCredentialsSize` / `ReadCredentialsBuffer` | `credman` | The blob the wallet registered, read at an offset. Format is entirely the wallet's own |
| `GetWasmVersion` | `credman` | Host ABI version — the feature-detection hook for `credman_v2` |
| `AddStringIdEntry` / `AddFieldForStringIdEntry` | `credman` | v1 emission: one flat entry plus its display fields |
| `AddEntrySet` / `AddEntryToSet` / `AddFieldToEntrySet` | `credman_v2` | v2 emission: grouped entries. Required for DCQL `credential_sets`, and carries a free-form `metadata` string |
| `fd_write`, `fd_seek`, `fd_close`, `fd_fdstat_get`, `proc_exit` | `wasi_snapshot_preview1` | The host provides a WASI preview-1 subset |

## Exports

`_start` and `memory`. Nothing else.

## Why this settles the toolchain

Because the host already speaks WASI preview 1, Rust's stock `wasm32-wasip1`
target drops straight in: no custom shim, no `no_std`, and `std` collections
and formatting stay available. Verified — a `wasm32-wasip1` build of this
workspace produces the same import and export shape as the C++ reference.

## Constraints that follow

- **A trap is a silent failure.** If the module panics, the picker shows no
  entries, which is indistinguishable from "no matching credential". There is
  no error surface at all. Hence `panic = "abort"` and the denied `unwrap` /
  `expect` lints.
- **`credman_v2` is not universal.** Feature-detect with `GetWasmVersion` and
  fall back to v1 emission. A missing import is a link failure, not a runtime
  `None`.
- **No network, no filesystem, hard time budget.** Everything the matcher needs
  arrives through the two buffers above.
