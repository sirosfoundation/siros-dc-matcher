# siros-dc-matcher

A credential matcher for the W3C Digital Credentials API on Android, the DCQL
engine behind it, and typed bindings of the Credential Manager host ABI, as a
Rust workspace.

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

Rust, pinned exactly in `rust-toolchain.toml` (rustup installs it on first use), plus the wasm target:

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
Manager ABI, so its `tests/matcher_wasm/` drives the same `.wasm` a device
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
cargo clippy --locked -p android-credman-sys -p android-credman \
  --target wasm32-wasip1 -- -D warnings
python3 scripts/check_panic_sites.py Cargo.toml
make matcher && python3 scripts/check_matcher_abi.py \
  target/wasm32-wasip1/wasm-release/matcher.wasm
make check-bindings    # committed bindings match the current API
cargo publish --locked --dry-run -p siros-dcql
cargo +1.82 check --locked --all-features \
  -p siros-dcql -p siros-dc-matcher-core -p siros-dc-matcher-wasm \
  -p android-credman-sys -p android-credman
cargo +1.82 check --locked --all-features --target wasm32-wasip1 \
  -p siros-dc-matcher-wasm -p android-credman-sys -p android-credman
cargo semver-checks --package siros-dcql
```

The last three need `rustup toolchain install 1.82 --target wasm32-wasip1`
and `cargo install cargo-semver-checks --locked`.

CI also enforces three things a green build does not imply:

- **No panic outside the tests and the matcher.** Each crate root but the
  matcher's forbids clippy's panic lints outside the tests.
  `scripts/check_panic_sites.py` fails on a root without them and finds the
  panics no lint covers: `assert!`, the std methods that panic on an
  argument, map indexing and division by a value.
- **Host ABI imports.** `scripts/check_matcher_abi.py` checks each import of
  `matcher.wasm`, with its signature, against the Credential Manager ABI
  table and the WASI functions the host provides.
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
| [`android-credman-sys`](crates/android-credman-sys) | `wasm32` | The Credential Manager host imports, one module per host level. [`ABI.md`](crates/android-credman-sys/ABI.md) is the contract and its evidence. |
| [`android-credman`](crates/android-credman) | any | The host ABI as types: nullability, version gating, set shape. |
| [`siros-dcql`](crates/siros-dcql) | any | OpenID4VP 1.0 DCQL: claims-path pointers (§7), credential and credential-set queries (§6.1–6.3), selection (§6.4). No I/O, no platform. Published to crates.io. |
| [`siros-dc-matcher-core`](crates/siros-dc-matcher-core) | any | The credential blob and its CBOR codec, the match profile and its evaluator, protocol dispatch, purpose lines, and the `zkp_req` planner and response check. |
| [`siros-dc-matcher-wasm`](crates/siros-dc-matcher-wasm) | `wasm32-wasip1` | The matcher binary. Ships `matcher.wasm`. |
| [`siros-dc-matcher-ffi`](crates/siros-dc-matcher-ffi) | UniFFI | Kotlin and Swift surface: build the registration blob, run the same match in-process, and plan a `zkp_req` query. |
| [`siros-dc-matcher-testhost`](crates/siros-dc-matcher-testhost) | native, dev | A wasmtime host implementing the Credential Manager ABI, so the shipping `.wasm` is testable off-device. |

[`docs/abi.md`](docs/abi.md) covers the host ABI as `matcher.wasm` uses it.
[`docs/zkp_req_request.md`](docs/zkp_req_request.md) and
[`docs/zkp_req_response.md`](docs/zkp_req_response.md) cover the `zkp_req` request and
presentation.

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

BSD-2-Clause; see [LICENSE](LICENSE). `crates/android-credman-sys` and
`crates/android-credman` are MIT OR Apache-2.0, copyright Frédéric Nieto,
from
[APTITUDE-Consortium/dcapi-matcher](https://github.com/APTITUDE-Consortium/dcapi-matcher);
this repository uses them under MIT.
