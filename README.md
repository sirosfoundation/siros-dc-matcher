# siros-dc-matcher

The SIROS wallet core, a Rust workspace: the components a wallet presents
credentials with over OpenID4VP 1.0 and the W3C Digital Credentials API, from
request intake to the response — DCQL, SD-JWT VC and ISO mdoc, issuer trust,
display, transaction data on the PaSO model, `zkp_req` proofs and the
presentation component — together with the credential picker Android's
Credential Manager runs (`matcher.wasm`), Kotlin and Swift bindings, and the
`zkp_req` provers with their browser presenter.

On Android, a wallet does not answer a `navigator.credentials.get({digital: …})`
call directly. It registers a snapshot of its credentials with Play Services
ahead of time, and Play Services runs a **matcher** — a WebAssembly module —
inside the credential-picker process to decide which credentials to offer. The
wallet app is launched only after the user picks one.

`matcher.wasm` is that module: the credential picker of the wallet core. It
runs the presentation component's matching, the matching of the wallet's own
plan, over the **registration** the wallet writes with `siros-registration`.
Its rules are code, versioned with the binary.

Released artifacts are on the
[releases page](https://github.com/sirosfoundation/siros-dc-matcher/releases):
`matcher.wasm` and its digest, an Android AAR, and an XCFramework.
`siros-dcql` is on [crates.io](https://crates.io/crates/siros-dcql).

## Overview

![The crates of the workspace in five layers, the artifacts built from them, and the host each platform provides](docs/ecosystem.svg)

`scripts/gen_ecosystem_svg.py` writes the diagram; change it there when a crate is added, renamed or removed.

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
`siros-picker-testhost` is a wasmtime host implementing the Credential
Manager ABI, so `crates/siros-picker-testhost/tests/matcher_wasm/` drives the same `.wasm` a device
would run. It builds the module on demand, so `make matcher` is not a
prerequisite — but without the wasm target installed those tests **fail**,
deliberately, rather than skipping and reporting a green run that checked
nothing.

Before pushing, what CI will check:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked -p siros-picker --target wasm32-wasip1 \
  --profile wasm-release -- -D warnings
cargo clippy --locked -p android-credman-sys -p android-credman \
  --target wasm32-wasip1 -- -D warnings
make matcher && python3 scripts/check_matcher_abi.py \
  target/wasm32-wasip1/wasm-release/matcher.wasm
make check-bindings    # committed bindings match the current API
cargo publish --locked --dry-run -p siros-dcql
cargo semver-checks --package siros-dcql   # cargo install cargo-semver-checks --locked
```

What links into the picker holds Rust 1.82 (`rustup toolchain install 1.82`):

```sh
export RUSTUP_TOOLCHAIN=1.82
cargo check --locked --all-features \
  -p siros-codec -p siros-dcql -p siros-dc-matcher-core -p siros-picker \
  -p android-credman-sys -p android-credman \
  -p siros-zkp-req -p siros-zkp-req-nym-auth -p siros-sdjwt -p siros-mdoc \
  -p siros-wallet-state -p siros-credential -p siros-display -p siros-transaction-data \
  -p siros-trust -p siros-registration
cargo check --locked -p siros-oid4vp
cargo check --locked -p siros-trust
cargo check --locked -p siros-presentation --no-default-features
cargo check --locked -p siros-transaction-data --no-default-features
cargo check --locked --all-features --target wasm32-wasip1 \
  -p siros-picker -p android-credman-sys -p android-credman
```

The proof backends and the browser presenter are in the `proving/` workspace; its CI runs from
there:

```sh
cd proving
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/fetch-artifacts.sh && cargo test --locked --release -p siros-zkp-proving-e2e -- --ignored
cargo clippy --locked -p siros-zkp-req-wasm --target wasm32-unknown-unknown \
  -- -D warnings       # after rustup target add wasm32-unknown-unknown
```

CI also enforces two things a green build does not imply:

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

`make aar` bundles `matcher.wasm` as an asset alongside the native library.
The picker reads the registration `siros-registration` writes; the FFI's
`SirosBlobBuilder` writes the v1 blob of `siros-dc-matcher-core`.

Two profile details are load-bearing and easy to undo:

- `[profile.release]` sets `strip = "debuginfo"`, not `strip = true`. Full
  stripping removes UniFFI's metadata symbols, and binding generation then
  produces no files and exits 0.
- `[profile.release]` keeps `panic = "unwind"`, because UniFFI catches panics
  at the boundary. Only `wasm-release` aborts.

## Crates

| Crate | Target | Contents |
|---|---|---|
| [`siros-codec`](crates/siros-codec) | any | The encodings every crate shares: a strict CBOR reader and deterministic writer, strict JSON, base64 and base64url, dates. |
| [`siros-dcql`](crates/siros-dcql) | any | OpenID4VP 1.0 DCQL: claims-path pointers (§7), credential and credential-set queries (§6.1–6.3), selection (§6.4). No I/O, no platform. Published to crates.io. |
| [`siros-oid4vp`](crates/siros-oid4vp) | any | OpenID4VP 1.0: the picker's request reading (`UnverifiedRequest`), and with `crypto` request intake, handovers, the `vp_token` and its submission. |
| [`siros-sdjwt`](crates/siros-sdjwt) | any | SD-JWT VC: the stored credential, disclosure selection, and the presentation with its KB-JWT signing input. |
| [`siros-mdoc`](crates/siros-mdoc) | any | ISO/IEC 18013-5 mdocs: the stored credential, element selection, `DeviceResponse` and the device signature's signing input. |
| [`siros-zkp-req`](crates/siros-zkp-req) | any | The `zkp_req` protocol layer: the query and its options, the usable pair, the presentation and the `vp_token`, the Verifier's structural checks. |
| [`siros-zkp-req-nym-auth`](crates/siros-zkp-req-nym-auth) | any | The nym_auth catalogue and its Longfellow and Vega systems: session binding, credential checks, the request policy, the presenter and verifier around a host's prover. |
| [`siros-trust`](crates/siros-trust) | any | Issuer trust: the trust store, issuer chains and their path validation, DCQL `trusted_authorities`, and the issuer facts the picker admits by. |
| [`siros-wallet-state`](crates/siros-wallet-state) | any | The decrypted wallet state of the private data container: credentials, presentation records, key ids. |
| [`siros-credential`](crates/siros-credential) | any | The format-independent credential: typed claims read by claims path, validity, instance choice, and the claim tree the registration carries. |
| [`siros-display`](crates/siros-display) | any | Display in the wallet's one language: cards, claim labels and rows, purpose lines, proof statement rows, picker fields. |
| [`siros-transaction-data`](crates/siros-transaction-data) | any | OpenID4VP transaction data on the PaSO model: definitions and their sources, projection, payload conformance, images, rendering, selection and the KB-JWT binding. |
| [`siros-presentation`](crates/siros-presentation) | any | The presentation component: the plan of a request over the wallet's credentials, the consent view and the response; without `wallet`, the matching the picker runs. |
| [`siros-registration`](crates/siros-registration) | any | The picker's registration: the projection of the wallet's credentials the wallet writes (feature `wallet`) and the picker reads. |
| [`siros-picker`](crates/siros-picker) | `wasm32-wasip1` | The credential picker over the presentation component's matching. Ships `matcher.wasm`. |
| [`android-credman-sys`](crates/android-credman-sys) | `wasm32` | The Credential Manager host imports, one module per host level. [`ABI.md`](crates/android-credman-sys/ABI.md) is the contract and its evidence. |
| [`android-credman`](crates/android-credman) | any | The host ABI as types: nullability, version gating, set shape, the picked entry. |
| [`siros-picker-testhost`](crates/siros-picker-testhost) | native, dev | A wasmtime host implementing the Credential Manager ABI, so the shipping `.wasm` is testable off-device. |
| [`siros-dc-matcher-core`](crates/siros-dc-matcher-core) | any | For the FFI: the v1 credential blob and its CBOR codec, the match profile and its evaluator. |
| [`siros-dc-matcher-ffi`](crates/siros-dc-matcher-ffi) | UniFFI | Kotlin and Swift surface: build the v1 blob, run the core's match in-process, and present and verify `zkp_req`. |
| [`siros-zkp-backend-longfellow`](proving/siros-zkp-backend-longfellow) | any | The Longfellow nym_auth system on `longfellow-libzk-v1`: zk-cred-longfellow behind the rulebook's artifact pins. In `proving/`. |
| [`siros-zkp-backend-vega`](proving/siros-zkp-backend-vega) | any | The Vega nym_auth system on `vega-v1`: zk-cred-vega behind the rulebook's artifact pins. In `proving/`. |
| [`siros-zkp-req-wasm`](proving/siros-zkp-req-wasm) | `wasm32-unknown-unknown` | The `zkp_req` presenter for the browser, with both provers, built with `wasm-pack`. In `proving/`. |
| [`siros-zkp-proving-e2e`](proving/e2e) | native, dev | Real proofs of both nym_auth systems through the presenter and the Verifier. In `proving/`. |

[`docs/zkp_req_core.md`](docs/zkp_req_core.md) covers the `zkp_req` crates, their API and the
prover interface.

## The registration

The wallet registers the projection of its credentials together with
`matcher.wasm`, and registers again when its credentials, trust store,
language or transaction metadata change. Per credential it holds the typed
claims, the card and claim labels in the wallet's language, the issuer facts
the trust store gave at registration, and the transaction data definitions
the credential is served by. The picker offers what the wallet's plan offers,
except where the plan reads what the projection leaves out: the `zkp_req`
credential tests and seed, the issuer certificates' validity at request time,
ad-hoc transaction metadata and remote images. The wallet decides those after
the pick.

## Privacy note

The registration contains claim *values*, not only labels, because the
picker evaluates a verifier's DCQL query against them before any UI is shown.
It holds no delivered or derived secret and no nym_auth undisclosable
attribute.
This is inherent to how the Credential Manager registry works and is equally
true of the stock matcher. It is recorded here so that it is understood up
front rather than rediscovered later as a finding.

## Acknowledgements

Multipaz's [C++ matcher](https://github.com/openwallet-foundation/multipaz)
(Apache-2.0) showed that a wallet-supplied matcher is practical, and serves as
this project's conformance oracle. An oracle, not a source — see
[CONTRIBUTING.md](CONTRIBUTING.md#provenance).

## Licence

BSD-2-Clause; see [LICENSE](LICENSE). `crates/android-credman-sys` and
`crates/android-credman` are MIT OR Apache-2.0, copyright Frédéric Nieto,
from
[APTITUDE-Consortium/dcapi-matcher](https://github.com/APTITUDE-Consortium/dcapi-matcher);
this repository uses them under MIT.
