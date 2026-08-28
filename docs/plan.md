# Plan

Ordered so the riskiest unknown dies first. Phase 1 answers "can we replace the
stock matcher on a real device at all" before any effort goes into a DCQL
engine. Estimates are focused engineering time.

The full write-up, including the requirements analysis this came from, is at
<https://claude.ai/code/artifact/289c7f68-73f0-410b-ad44-17c5c20252c4>.

| Phase | Work | Estimate |
|---|---|---|
| 0 | Repo bootstrap under the settled licensing rules | done |
| 1 | Prove the matcher swap on hardware | done |
| 2 | Credential blob format and builder | done |
| 3 | The DCQL engine | done (publish blocked) |
| 4 | Profile evaluator and the ZK path | ~1 week |
| 5 | Entry emission and display | ~3 days |
| 6 | Kotlin SDK integration | ~1 week |
| 7 | Swift parity and first release | ~3 days |

## Phase 0 — Bootstrap ✅

Workspace, BSD-2-Clause licence, the provenance rule in `CONTRIBUTING.md`
before any matching code exists, CI mirroring the house setup, and the
crates.io publishing path for `siros-dcql`.

**Done.** All four workflows green on the first commit. One item outstanding,
and it needs an account rather than code: the crates.io owner and the
`CARGO_REGISTRY_TOKEN` repository secret, without which the Phase 3 release job
cannot publish `siros-dcql`.

## Phase 1 — Prove the swap on hardware

A matcher that reads the request and emits one fixed entry, plus the wasmtime
test host implementing every import in `abi.rs`. Register it from the Kotlin
sample app in place of `OpenId4VpRegistry`, and confirm the entry appears in a
real picker on a real device.

Everything after this is incremental. If this does not work, nothing else
matters.

The entry reports what the matcher observed — host ABI version, verified
calling package and origin, and the size of the registered blob — rather than
being inert. That turns a hardware run into evidence about each leg of the
plumbing separately, instead of a single pass/fail.

**Software side done:** `matcher.wasm` builds at ~85 KB, runs under the test
host, and 16 tests pass including malformed-input cases that must never trap.
**Outstanding:** the on-device confirmation, which needs a phone.

## Phase 2 — Blob format and builder ✅

Versioned CBOR schema for credentials, display properties, icons and the match
profile, in `siros-dc-matcher-core::db`. `SirosBlobBuilder` exposes it through
UniFFI, and owns the profile itself — wallets differ in what they *hold* and
what they *can do*, not usually in how DCQL should be interpreted, and keeping
the interpretation in one place is what stops two SDKs drifting apart on it.

Golden vectors are committed under `crates/siros-dc-matcher-core/tests/golden/`.
Round-trip tests cannot catch encoder/matcher drift, because both ends move
together in a round trip; a committed byte vector is the only thing that
notices when today's encoder stops producing what a shipped matcher decodes.

The matcher now decodes the blob it is handed and reports what it found, so a
blob it cannot read is distinguishable from a wallet with nothing to offer —
identical in the picker, and only one of them is a bug.

**Watch item:** `matcher.wasm` grew from 85 KB to 183 KB when CBOR decoding
landed. Still inside the 300 KB budget, but Phase 3 adds DCQL on top of it. If
the budget gets tight, the request-side JSON parser is the thing to replace,
not the blob format.

## Phase 3 — The DCQL engine ✅

Full DCQL 1.0 in `siros-dcql`: the query model (§6.1–6.3), claims path
pointers (§7.1 JSON and §7.2 mdoc), and selection (§6.4) — `claims`,
`claim_sets` with first-satisfiable-option preference, `values` filtering,
and `credential_sets` with required and optional options.

Two rules drove the design, and both silently change what a wallet offers if
missed:

- **A credential missing a requested claim must not be offered at all**
  (§6.4.1). Not a weak match — not a match. Filtering on format and metadata
  alone, which is what the Kotlin SDK does today, offers credentials that
  cannot satisfy the request.
- **An absent `credential_sets` means every query must be satisfied** (§6.4),
  not "no constraint". Reading it the other way reports a request as
  satisfiable when half of it cannot be answered.

`meta` is deliberately not interpreted here: §6.1 defines it per credential
format, so a generic engine cannot evaluate it. That is what the `Policy`
trait is for, and where the match profile plugs in at Phase 4.

Tested against the specification's own vectors from
`openid/OpenID4VP/1.0/examples/query_lang`, committed under
`crates/siros-dcql/tests/spec_vectors/`. They caught a real weakness in the
test fixtures — nested paths like `["address", "street_address"]` and `values`
restrictions — which is exactly why vectors written by someone else are worth
more than ones shaped by this implementation's assumptions.

**Outstanding:** publishing `siros-dcql 0.1.0` needs the crates.io owner and
`CARGO_REGISTRY_TOKEN`, which is still the one item blocked on an account
rather than on code. The release job is written and `cargo publish --dry-run`
passes in CI on every PR.

## Phase 4 — Profile evaluator and the ZK path

Format rules, meta rules, capability predicates, protocol dispatch, and the
strict/permissive fallback. Then the reason this project exists:
`mso_mdoc_zk` matching stored `mso_mdoc` credentials, gated on a satisfiable
`zk_system_type` entry *including its params* — `num_attributes` among them —
and `ppid_context` carried through.

Checking capability before the picker rather than during presentation is the
point. An entry the wallet cannot honour walks the user through consent and
then fails.

## Phase 5 — Entry emission and display

`credman_v2` entry sets with a v1 fallback, field display properties, icon
handling, and the `metadata` payload carrying the matched query id, the chosen
ZK system and the requested claims forward into the wallet activity.

## Phase 6 — Kotlin SDK integration

`SirosDigitalCredentialRegistry : DigitalCredentialRegistry`, shipped **in the
SDK rather than the sample app**. Registration, entry building and matching are
wallet logic every consumer needs, and all three currently live in
`sample-app`. The sample app drops to a one-line call, `CredentialMatcher.kt`
becomes a thin shim over the FFI engine, and the activity consumes the
matcher's metadata instead of re-deriving it.

## Phase 7 — Swift parity and first release

XCFramework build, `CredentialMatcher.swift` replaced by the shared engine, and
`v0.1.0` tagged with a reproducible `matcher.wasm` attached.

iOS OS-level DC API wiring stays where it is — a separate, already-tracked gap
— but the matching half is then done for it, since iOS has no WASM matcher
concept and does this in-process.
