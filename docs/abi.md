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
| `fd_write`, `fd_seek`, `fd_close`, `fd_fdstat_get`, `proc_exit` | `wasi_snapshot_preview1` | The host provides a WASI preview-1 *subset*. It is known to lack `random_get` (Rust `HashMap`'s default hasher needs it; see UbiqueInnovation/oid4vp-wasm-matcher). A missing import fails instantiation with no error surface — hence the Makefile stubs out the two `environ_*` imports rustc's CRT adds unconditionally |

## Exports

`_start` and `memory`. Nothing else.

## Why this settles the toolchain

Because the host already speaks WASI preview 1, Rust's stock `wasm32-wasip1`
target drops straight in: no custom shim, no `no_std`, and `std` collections
and formatting stay available. Verified — a `wasm32-wasip1` build of this
workspace produces the same import and export shape as the C++ reference.

## Host behaviours the emitter must respect

Neither is documented by the platform. Both were established on a real
device, from the host process's own logcat output.

- **An entry with no icon is dropped.** `AddEntryToSet` with a null icon
  pointer makes the host log `WasmRuntime: Null icon for icon` in its own
  process and show nothing for that entry. The wallet side sees only "your
  info wasn't found". An icon reference that resolves to nothing therefore
  costs the credential its *entry*, not just its picture — every entry must
  carry real image bytes, and 64×64 PNG is known to work (a 4×4 one was
  dropped just the same).
- **Declaring a set id twice discards the whole output.** Two `AddEntrySet`
  calls with the same id in one invocation make the host silently reject
  everything the matcher emitted — no log line at all. Every set id must be
  unique within an invocation.

Watch for both with `adb logcat | grep WasmRuntime` while the picker is open —
that tag is silent on success, so its absence proves nothing, but its
`Null icon` form is definitive.

## Constraints that follow

- **A trap is a silent failure.** If the module panics, the picker shows no
  entries, which is indistinguishable from "no matching credential". There is
  no error surface at all. Hence `panic = "abort"` and the denied `unwrap` /
  `expect` lints.
- **A v1 fallback cannot be a runtime branch.** WebAssembly imports resolve at
  instantiation, so a module that *declares* `credman_v2` fails to load on a
  host that lacks it, however carefully it inspects `GetWasmVersion` first.
  Supporting such a host means shipping a second binary that declares only the
  v1 functions — not an `if` inside this one. Every Play Services version
  currently shipping resolves the v2 imports, so that second binary does not
  exist yet.
- **`GetWasmVersion` is still worth reading.** It goes into entry metadata, so
  a field report says which host ABI produced the behaviour.
- **No network, no filesystem, hard time budget.** Everything the matcher needs
  arrives through the two buffers above.
