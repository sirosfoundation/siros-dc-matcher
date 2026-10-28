# Contributing

## Provenance

**Read this before writing any matching code.** It is committed ahead of the
implementation on purpose — a provenance rule written after someone has read the
source it governs is worth nothing.

This repository is an independent implementation of the OpenID4VP DCQL query
language and of the Android Credential Manager matcher ABI. It is licensed
BSD-2-Clause, except `crates/android-credman-sys` and `crates/android-credman`:
MIT OR Apache-2.0, used here under MIT.

The OpenWallet Foundation's [Multipaz](https://github.com/openwallet-foundation-labs/multipaz)
project ships an Apache-2.0 credential matcher that solves the same problem
(`multipaz-dcapi/src/androidMain/matcher/`). We use it as a **conformance
oracle** and nothing else.

This is not a formal clean-room procedure. Clean-room exists for
reverse-engineering undocumented interfaces, and nothing here is undocumented —
DCQL is a public specification and the matcher ABI is an interoperability
interface. What follows is the narrower rule that BSD-2 licensing actually
requires: no Apache-2.0 *expression* enters this codebase.

Two implementations of DCQL will converge on **behaviour**, because the
specification dictates it. That convergence is expected and fine. What must not
converge is **expression**: file decomposition, type structure, algorithm shape
carried over line by line, or comments.

### You may

- Use the host ABI — function names, signatures, module names, calling
  conventions. It is an interface required for interoperability.
  `android-credman-sys` declares it from Google's reference header.
- Run Multipaz's matcher binary and compare its output against ours.
- Commit behaviour observed that way as test vectors. A vector describing what a
  program does is a fact about it.
- Consult their source to answer "what does the host actually accept here?" when
  the specification is silent. Write the *fact* down, in your own words, in the
  code comment — never the passage that revealed it.

### You may not

- Copy or transliterate their source into Rust, in whole or in part. This
  applies with full force to `dcql.cpp`, `CredentialDatabase.cpp` and
  `Request.cpp`, which cover exactly the ground our core crates cover.
- Port their file or type decomposition structurally. This is the same problem
  as copying, and considerably harder to catch in review.
- Copy their comments, or adopt their identifier set wholesale.
- Vendor their binaries into this repository. Redistributing an Apache-2.0
  artifact from a BSD-2 tree drags in notice obligations for no benefit.

### Cite the spec, not the implementation

Every non-obvious matching rule carries a doc comment naming the section it
comes from — `OpenID4VP 1.0 §6.4.2`, `ISO/IEC 18013-7`, `W3C Digital
Credentials API`. A rule you cannot cite is a rule you should not be writing
yet: either it belongs to the configurable match profile rather than the engine,
or you have not finished reading.

Reviewers: treat an uncited behavioural rule as a review comment, and a
structural resemblance to the oracle as a blocker.

## Development

[README.md](README.md#build-and-test) gives the commands CI runs.

`siros-dcql` is published to crates.io and therefore may not depend on any other
crate in this workspace. CI enforces this with `cargo publish --dry-run`; please
do not work around it.

Everything that ships inside the credential picker holds Rust 1.82:
`siros-dcql`, `siros-dc-matcher-core`, `siros-dc-matcher-wasm`,
`android-credman-sys` and `android-credman`. The MSRV job checks them on 1.82,
for the host and for `wasm32-wasip1`.

`siros-dc-matcher-ffi` and `-testhost` declare 1.88 in their own manifests —
uniffi's bindgen chain and wasmtime both need it — and neither ships in the
picker. If you raise a floor, raise it in the manifest that owns it and say
why there.

Only the DC API matcher panics: `android-credman-sys`, `android-credman` and
`siros-dc-matcher-wasm`, where Credential Manager shows nothing on a trap.
Each of their panics carries an `#[expect(..., reason)]` that says why it
cannot recover. In every other crate a panic crashes the wallet, so nothing
panics outside the tests: a type makes the impossible state unrepresentable,
or the caller receives an error. CI holds each crate to it with clippy and
`scripts/check_panic_sites.py`.

## Changelog

Changes that a user or a downstream consumer would notice go in
[`CHANGELOG.md`](CHANGELOG.md), under `Unreleased`, in the same PR. Changes to
`siros-dcql`'s public API also go in [its own
changelog](crates/siros-dcql/CHANGELOG.md), which is versioned independently
because the crate is released on crates.io on its own schedule.

Releasing renames `Unreleased` to the version and dates it; that is the only
time the heading changes.

A breaking change to `siros-dcql` needs a minor bump — pre-1.0 that is what
`cargo semver-checks` demands, and it will fail the build until the version
admits to the change.

## Pull requests

Branch from `main`, open a PR, keep the history linear. Every PR must be green on
CI — including the WASM size gate, which fails the build when `matcher.wasm`
grows past its budget. If your change legitimately needs the extra bytes, raise
the budget in the same PR and say why in the commit message.
