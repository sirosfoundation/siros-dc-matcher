# siros-dc-matcher

An open, configurable credential matcher for the W3C Digital Credentials API.

On Android, a wallet does not answer a `navigator.credentials.get({digital: …})`
call directly. It registers a snapshot of its credentials with Play Services
ahead of time, and Play Services runs a **matcher** — a WebAssembly module —
inside the credential-picker process to decide which credentials to offer. Only
after the user picks one does the wallet app get launched.

The matcher that ships with AndroidX understands two credential formats:
`mso_mdoc` and `dc+sd-jwt`. Anything else — a ZK-wrapped presentation, a
pseudonymous credential, a format that does not exist yet — produces no picker
entry at all, and the wallet is simply never offered.

This workspace replaces that matcher with one whose rules live in configuration
rather than in the binary.

## Status

**Phase 0 — scaffolding.** The crates below are skeletons. The host ABI in
`siros-dc-matcher-wasm` is real and verified; the matching engines are not yet
implemented. See [`docs/plan.md`](docs/plan.md) for the phased plan.

## Crates

| Crate | Target | Responsibility |
|---|---|---|
| [`siros-dcql`](crates/siros-dcql) | any | DCQL 1.0 as a standalone library: parse, evaluate against an abstract store, enumerate credential-set combinations. No I/O, no platform. Published to crates.io. |
| [`siros-dc-matcher-core`](crates/siros-dc-matcher-core) | any | Credential-blob model and CBOR codec, the match profile and its evaluator, protocol dispatch, and the `PickerSink` emission trait. |
| [`siros-dc-matcher-wasm`](crates/siros-dc-matcher-wasm) | `wasm32-wasip1` | The matcher binary itself. Ships `matcher.wasm`. |
| [`siros-dc-matcher-ffi`](crates/siros-dc-matcher-ffi) | UniFFI | Kotlin/Swift surface — build the registration blob, and run the same match in-process. |
| [`siros-dc-matcher-testhost`](crates/siros-dc-matcher-testhost) | native, dev | A wasmtime host implementing the full Credential Manager ABI, so the real `.wasm` is testable in CI rather than only on a device. |

## Configuration, not recompilation

The matcher is a binary inside an APK, so a rebuild is a release cycle. The
matching rules therefore do not live in the binary — they travel with the
registered credential blob as a **match profile**: which protocols to accept,
which query formats map to which stored formats, how `meta` keys constrain a
match, and what this wallet is actually capable of producing.

Adding a credential format becomes a configuration change and a
re-registration, which every wallet already performs whenever its credential set
changes.

The profile is deliberately not a programming language. Its operator set is
fixed (`eq`, `in`, `prefix`, `exists`, `ignore`) with no arithmetic and no
user-supplied expressions. Anything beyond that boundary is a matcher release,
not a config change.

## Privacy note

The registered blob contains claim *values*, not just labels, because the
matcher has to evaluate a verifier's DCQL query against them before any UI is
shown. This is inherent to how the Credential Manager registry works and is
equally true of the stock matcher. It is written down here so it is understood
up front rather than rediscovered as a finding later.

## Acknowledgements

Multipaz's [C++ matcher](https://github.com/openwallet-foundation-labs/multipaz)
(Apache-2.0) demonstrated that a wallet-supplied matcher is practical, and serves
as this project's differential-testing oracle. It is an oracle, not a source —
see [CONTRIBUTING.md](CONTRIBUTING.md#provenance).

## Licence

BSD-2-Clause. See [LICENSE](LICENSE).
