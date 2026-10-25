# The Credential Manager matcher ABI

The full host ABI, with its evidence, is
[`crates/android-credman-sys/ABI.md`](../crates/android-credman-sys/ABI.md).

## Imports

`matcher.wasm` needs host level 2.

| Function | Module | Purpose |
|---|---|---|
| `GetWasmVersion` | `credman` | Host ABI level. Below 2 the matcher emits nothing |
| `GetCallingAppInfo` | `credman` | Writes `{package_name[256], origin[512]}` into guest memory — the platform-verified caller |
| `GetRequestSize` / `GetRequestBuffer` | `credman` | The DC API request JSON, shaped `{"requests":[{"protocol":…,"data":…}]}` |
| `GetCredentialsSize` / `ReadCredentialsBuffer` | `credman` | The blob the wallet registered, read at an offset until complete |
| `AddEntrySet` / `AddEntryToSet` / `AddFieldToEntrySet` | `credman_v2` | Grouped entries. Required for DCQL `credential_sets`, and carries a free-form `metadata` string |
| `fd_write`, `proc_exit` | `wasi_snapshot_preview1` | The host provides `fd_write`, `fd_seek`, `fd_close`, `fd_fdstat_get` and `proc_exit`, and lacks `random_get`, which std's default hasher reads; `clippy.toml` forbids std's hash collections. The Makefile stubs out the two `environ_*` imports rustc's CRT adds |

## Exports

`_start` and `memory`, which the host uses, and `__main_void`, from
wasi-libc.

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

## The request, and its three shapes

`GetRequestBuffer` hands over the DC API request as JSON. The envelope is the
same whichever protocol the verifier used — a `requests` array, because one
call can offer the same request under several and let the wallet pick. Only
`data` differs (OpenID4VP 1.0 Appendix A):

```json
{"requests": [
  {"protocol": "openid4vp-v1-unsigned",    "data": { … request object, dcql_query inline … }},
  {"protocol": "openid4vp-v1-signed",      "data": {"request": "<header>.<payload>.<signature>"}},
  {"protocol": "openid4vp-v1-multisigned", "data": {"request": {"payload": "<base64url>", "signatures": [ … ]}}}
]}
```

For `-signed`, the payload is the compact JWS's middle segment. For
`-multisigned`, it is the `payload` member of a JWS JSON Serialization object —
which the reference matcher also accepts at the top level of `data`, so we
accept both. Base64url-decoded, either is the same JSON the unsigned form
carries directly:

```json
{"client_id": "x509_san_dns:verifier.example", "response_mode": "dc_api.jwt",
 "nonce": "…", "expected_origins": ["https://verifier.example"],
 "dcql_query": { … }, "client_metadata": {"jwks": { … }}}
```

**The matcher does not verify signatures, and must not be relied on as though
it did.** It has no crypto, no randomness and a hard size budget, and it is not
the trust boundary: the wallet verifies the JWS at selection time, before
anything is disclosed. The matcher decodes an unverified payload for one
reason — to find `dcql_query` and decide what to draw in the picker.

A request shape this build cannot read declines *that protocol* rather than
failing the call, so the verifier's negotiation still works: offer signed and
unsigned together and the readable one is answered.

## Constraints that follow

- **A trap is a silent failure.** If the module panics, the picker shows no
  entries, which is indistinguishable from "no matching credential". There is
  no error surface at all. Hence `panic = "abort"` and the denied `unwrap` /
  `expect` lints.
- **No v1 fallback.** Below host level 2 the matcher emits nothing. A missing
  import traps only when called (`ABI.md` §3), so a runtime branch on
  `GetWasmVersion` could serve a level-1 host.
- **`GetWasmVersion` goes into entry metadata**, so a field report says which
  host ABI produced the behaviour.
- **No network, no filesystem, hard time budget.** Everything the matcher needs
  arrives through the two buffers above.
