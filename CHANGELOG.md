# Changelog

Notable changes to the matcher, its AAR/XCFramework, and the `siros-dcql`
crate. The crate keeps [its own changelog](crates/siros-dcql/CHANGELOG.md),
because it is published to crates.io and versioned independently of this
repository.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are reconstructed from git history for releases made before this file
existed.

## Unreleased

### Fixed

- The dropped-combination count says whether it is exact. The number of
  combinations is a product of the per-query candidate counts, and a wallet
  holding enough credentials overflows it — at which point the count of what
  was skipped is a lower bound rather than a figure. It reported
  18446744073709551551, which is true as a bound and ruinous as a number.
  Entry metadata gains `combinations_dropped_is_exact`, and the FFI outcome
  gains the matching field; what the matcher offers is unaffected, since the
  overflow is in the count and never in the entries.
- A verifier requiring cryptographic holder binding is honoured (§6.1). The
  field was parsed and never read, and since its default is `true`, that
  applied to every verifier that said nothing about it as well as to those that
  asked explicitly. Every credential the wallet registers is bound to a WSCD
  key, so nothing the matcher offers today changes — but the requirement is now
  enforced rather than assumed.
- `multiple` (§6.1) is honoured: a verifier asking for several credentials of
  one type now receives every match, instead of the flag being ignored.
- Duplicate DCQL identifiers are rejected rather than resolving to whichever
  came first. A repeated credential query `id` (§6.1) or claims `id` (§6.3)
  made a reference from `credential_sets` or `claim_sets` ambiguous, and the
  engine answered one of them — a request that asked for two credentials was
  quietly answered with one, and the picker offered the same credential twice
  as separate options.
- `zk_required` absent now means the proof is *optional*. It was read as
  "required", the inverse of the specified behaviour, which silently withheld
  the wallet from every verifier that named `zk_system_type` without also
  sending a flag — precisely the migration path off the `mso_mdoc_zk` format
  suffix. (#27)

### Added

- The picker shows the verifier's stated reason. A §6.2 `purpose` is rendered
  on each entry of the combination it belongs to, so a person is told what the
  disclosure is *for* and not merely that one is being asked of them. A reason
  that is absent, empty or blank produces a null pointer rather than an empty
  label — the host renders the presence of that field, which is what put a
  warning triangle on every entry before v0.6.2.
- A §6.2 `purpose` now reaches the caller. `FfiCombination.purposes` carries
  the verifier's stated reason for each combination, rendered for display, so a
  wallet can tell the user what they are consenting to rather than only that
  they are. A string arrives unchanged; an integer or object keeps its JSON
  form instead of being dropped.
- A minimum-supported-Rust-version job, so the declared `rust-version = 1.82`
  is a tested claim rather than an assertion.
- `cargo-semver-checks` on `siros-dcql`, so a change to a published API cannot
  merge without a version bump that admits to it.
- This changelog, and one for `siros-dcql`.

## v0.6.2 — 2026-09-07

### Fixed

- Picker entries no longer carry a warning symbol. Every entry was emitted with
  an empty-string `warning`, and the host renders the presence of the field
  rather than its content, so all of them showed a warning triangle with
  nothing behind it. The field is now a null pointer when there is nothing to
  say.

## v0.6.1 — 2026-09-05

### Fixed

- The release publishes the `matcher.wasm` that actually ships. The job built
  the module and attached it without the strip step the AAR's copy goes
  through, so the published artifact and the shipped one were different
  binaries with the same name.

### Changed

- Error documentation names the types a caller can catch in the language they
  will catch them in, once, rather than per variant.

## v0.6.0 — 2026-09-04

### Added

- Signed and multisigned requests. `openid4vp-v1-signed` and
  `openid4vp-v1-multisigned` are answered by reading the DCQL query out of the
  JWS payload. The signature is deliberately *not* verified here — a matcher
  has no trust anchors and no network — so this is request *parsing*, and the
  presentation path remains where verification belongs.
- A typed reason for every request the matcher cannot use, so an unreadable
  request is distinguishable from an unsupported protocol rather than both
  producing an empty picker.
- Every picker entry carries an icon, and each invocation emits exactly one set
  id. An entry with a null icon is silently dropped by the host, and a repeated
  set id discards the whole output — both fail as "no matching credential".

### Fixed

- The accepted request *shape* follows the protocol label. A compact JWS is no
  longer accepted under an `-unsigned` label, nor an inline object under a
  signed one, so a signed payload cannot be answered as though it had arrived
  unsigned.
- A JWE is rejected rather than having its encrypted key decoded as a payload.
- Allocation fails on overflow instead of wrapping.
- The two WASI imports rustc's CRT adds unconditionally are stubbed, keeping
  the module loadable by a host that provides only `credman` and a WASI subset.

### Note

- 0.5.0 was bumped in-tree but never tagged or released.

## v0.4.0 — 2026-08-31

### Added

- A verifier can say whether a proof is actually required, rather than the
  matcher inferring it from the requested format.
- The ZK capability check triggers on the presence of `zk_system_type`, not on
  the `mso_mdoc_zk` format suffix, which the flag is intended to replace.

## v0.3.0 — 2026-08-31

### Added

- Complete per-query candidates across the FFI boundary, so a caller can see
  every credential that satisfies each query rather than only that one did.
- The release publishes an XCFramework alongside the AAR.

## v0.2.0 — 2026-08-30

### Added

- Matching across the FFI boundary, generating Kotlin and Swift bindings from
  one Rust implementation.

### Fixed

- The FFI library unwinds instead of aborting. UniFFI turns a panic in exported
  code into an error using `catch_unwind`, which cannot happen in an aborting
  build: the bindings looked like they handled errors while any panic took down
  the host application. CI now measures the unwinding tables in the shipped
  artifact, because `cargo test` always builds with unwinding and so can never
  observe what ships.

## v0.1.0 — 2026-08-30

First release. The matcher runs inside the Android credential picker as a WASM
module, evaluates a DCQL query against a compact credential blob, and emits
picker entries through the host's `credman` ABI.

### Added

- The credential blob format, its UniFFI builder, and golden vectors.
- A DCQL engine (OpenID4VP 1.0 §6) with claims path pointers (§7).
- The profile evaluator, format and metadata matching, and the `mso_mdoc_zk`
  path.
- Real `credential_sets` combination enumeration and picker entry emission.
- Packaging: the matcher and its encoder ship as one AAR.
- Releases publish through trusted publishing rather than a stored token.
