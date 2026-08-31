# siros-dc-matcher

A credential matcher for the W3C Digital Credentials API on Android, plus the
DCQL engine behind it, as a Rust workspace.

On Android, a wallet does not answer a `navigator.credentials.get({digital: …})`
call directly. It registers a snapshot of its credentials with Play Services
ahead of time, and Play Services runs a **matcher** — a WebAssembly module —
inside the credential-picker process to decide which credentials to offer. The
wallet app is launched only after the user picks one.

`matcher.wasm` is that module. Its rules come from a **match profile** carried
in the registered blob rather than compiled in, so which formats and protocols
a wallet answers is a re-registration rather than a release. The same matching
code is also exposed over UniFFI, so a wallet can run in-process the decision
the picker will make out-of-process.

Released artifacts are on the
[releases page](https://github.com/sirosfoundation/siros-dc-matcher/releases):
`matcher.wasm` and its digest, an Android AAR, and an XCFramework.
`siros-dcql` is on [crates.io](https://crates.io/crates/siros-dcql).

## Build and test

Rust stable, plus the wasm target:

```sh
rustup target add wasm32-wasip1
```

Then:

```sh
cargo test --locked --workspace --all-features   # libraries, FFI, and matcher.wasm
make matcher                            # target/wasm32-wasip1/wasm-release/matcher.wasm
```

`cargo test` covers the matcher binary too, not just the libraries.
`siros-dc-matcher-testhost` is a wasmtime host implementing the Credential
Manager ABI, so its `tests/matcher_wasm.rs` drives the same `.wasm` a device
would run. It builds the module on demand, so `make matcher` is not a
prerequisite — but without the wasm target installed those tests **fail**,
deliberately, rather than skipping and reporting a green run that checked
nothing.

Before pushing, what CI will check:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked -p siros-dc-matcher-wasm --target wasm32-wasip1 \
  --profile wasm-release -- -D warnings
make check-bindings    # committed bindings match the current API
cargo publish --locked --dry-run -p siros-dcql
```

CI also enforces two things a green build does not imply:

- **Host ABI symbols.** A matcher that fails to link traps, and a trapping
  matcher emits no entries — indistinguishable to a user from "no matching
  credential". The imports and exports are checked in the built module.
- **A 307,200-byte (300 KiB) size budget** for `matcher.wasm`, which runs in someone else's
  process. Raising it takes a line in `.github/workflows/ci.yml` and a reason.

### Bindings and mobile artifacts

Generated bindings are committed under `bindings/`, so consumers do not need
UniFFI to build. Regenerate after any change to the FFI surface — including doc
comments, which are copied through verbatim:

```sh
make bindings          # Kotlin + Swift
make check-bindings    # what CI runs; fails if the committed copies are stale
```

Packaging needs a toolchain per platform:

```sh
cargo install cargo-ndk                    # Android
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
make aar pom
make publish-local                         # into ~/.m2, for a local Gradle build

rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
make xcframework                           # macOS only
```

`make aar` bundles `matcher.wasm` as an asset alongside the native library, so
a wallet gets the blob's writer and its reader from one dependency at one
version.

Two profile details are load-bearing and easy to undo:

- `[profile.release]` sets `strip = "debuginfo"`, not `strip = true`. Full
  stripping removes UniFFI's metadata symbols, and binding generation then
  produces no files and exits 0.
- `[profile.release]` keeps `panic = "unwind"`, because UniFFI catches panics
  at the boundary. Only `wasm-release` aborts.

## Crates

| Crate | Target | Contents |
|---|---|---|
| [`siros-dcql`](crates/siros-dcql) | any | OpenID4VP 1.0 DCQL: claims-path pointers (§7), credential and credential-set queries (§6.1–6.3), selection (§6.4). No I/O, no platform. Published to crates.io. |
| [`siros-dc-matcher-core`](crates/siros-dc-matcher-core) | any | The credential blob and its CBOR codec, the match profile and its evaluator, protocol dispatch, picker emission. |
| [`siros-dc-matcher-wasm`](crates/siros-dc-matcher-wasm) | `wasm32-wasip1` | The matcher binary. Ships `matcher.wasm`. |
| [`siros-dc-matcher-ffi`](crates/siros-dc-matcher-ffi) | UniFFI | Kotlin and Swift surface: build the registration blob, and run the same match in-process. |
| [`siros-dc-matcher-testhost`](crates/siros-dc-matcher-testhost) | native, dev | A wasmtime host implementing the Credential Manager ABI, so the shipping `.wasm` is testable off-device. |

[`docs/plan.md`](docs/plan.md) covers the design and the reasoning behind it.

## The match profile

Matching rules travel with the registered blob: which protocols to accept,
which query formats map to which stored formats, how `meta` keys constrain a
match, and what the wallet can actually produce.

The profile is not a programming language. Its operators are fixed — `eq`,
`in`, `prefix`, `exists`, `ignore` — with no arithmetic and no user-supplied
expressions. Anything past that boundary is a matcher release, not a config
change.

## Privacy note

The registered blob contains claim *values*, not only labels, because the
matcher evaluates a verifier's DCQL query against them before any UI is shown.
This is inherent to how the Credential Manager registry works and is equally
true of the stock matcher. It is recorded here so that it is understood up
front rather than rediscovered later as a finding.

## Acknowledgements

Multipaz's [C++ matcher](https://github.com/openwallet-foundation-labs/multipaz)
(Apache-2.0) showed that a wallet-supplied matcher is practical, and serves as
this project's differential-testing oracle. An oracle, not a source — see
[CONTRIBUTING.md](CONTRIBUTING.md#provenance).

## Licence

BSD-2-Clause. See [LICENSE](LICENSE).
