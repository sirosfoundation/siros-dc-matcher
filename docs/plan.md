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
| 3 | The DCQL engine | done, published |
| 4 | Profile evaluator and the ZK path | done |
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

**Published:** [`siros-dcql 0.1.0`](https://crates.io/crates/siros-dcql), the
first SIROS crate on crates.io.

Releases authenticate by **trusted publishing** rather than a stored token:
crates.io exchanges the workflow's OIDC identity for a credential that lives
30 minutes and is revoked when the job ends, so there is no long-lived
registry secret in this repository to leak or rotate. The Trusted Publisher is
bound to `sirosfoundation/siros-dc-matcher`, `release.yml`, environment
`crates-io` — renaming any of those without updating the configuration on
crates.io breaks publishing.

Note the ordering constraint that shaped this: a Trusted Publisher can only be
created after a crate exists, so 0.1.0 was published by hand and everything
after it is keyless.

## Phase 4 — Profile evaluator and the ZK path ✅

`evaluator::ProfilePolicy` supplies the half of matching DCQL leaves to the
deployment: format rules, meta rules, capability predicates, protocol
dispatch, and the strict/permissive fallback. §6.1 defines `meta` per
credential format, so a generic engine has nothing to evaluate it against —
that is why this lives here and not in `siros-dcql`.

**A `mso_mdoc_zk` request now reaches an ordinary stored `mso_mdoc`**, gated
on a `zk_system_type` entry this wallet can actually satisfy. Verified through
the real `matcher.wasm` in the test host, not just in unit tests.

Two details that are easy to get wrong and were got wrong before:

- **Parameters are sibling keys of `id`/`system`**, not a nested `params`
  object. A parser looking for `params` still finds `id` and `system`, so it
  parses without error while reading no parameters at all — and then matches a
  circuit the wallet does not have.
- **`num_attributes` is part of the match.** A ZK circuit is built for a fixed
  attribute count, so the right system with the wrong count is a proof this
  wallet cannot produce. Checking it before the picker is the whole point: an
  entry the wallet cannot honour walks the user through consent and then
  fails, which is how this first surfaced as
  `MDOC_VERIFIER_HASH_PARSING_FAILURE`.

`ppid_context` is carried to the wallet rather than used for matching — a
pseudonym context changes what is produced, not which credential can produce
it.

**Known limitation:** claims path pointers resolve only when every component
is a string. The blob records paths as strings, so a pointer containing `null`
or an array index cannot match. ISO mdoc is unaffected (§7.2.1 requires two
string components) and nested JSON *objects* are fine; only arrays are out of
reach, and no format SIROS issues today puts a requestable claim in one.
Widening it means giving the blob real value structure — a wire-format change,
deliberately not smuggled in here.

`org.iso.mdoc` is deliberately absent from the default profile. The profile
states what this wallet answers, and there is no ISO 18013-7 reader yet —
advertising it would make a request offering only that protocol look supported
and then match nothing. It goes back in the same change that adds a parser.

Candidates are emitted as separate single-member sets. A set means "these
entries are selected *together*", so putting alternatives in one would tell the
picker the user is disclosing all of them at once. Genuine multi-credential
sets arrive with `credential_sets` combinations in Phase 5.

**Size watch:** `matcher.wasm` is 232 KB against the 300 KB budget, 75% used.
Phase 5's display work is small, but the headroom is no longer generous.

## Phase 5 — Entry emission and display

`credman_v2` entry sets with a v1 fallback, field display properties, icon
handling, and the `metadata` payload carrying the matched query id, the chosen
ZK system and the requested claims forward into the wallet activity.

## Phase 6 — Kotlin SDK integration

**Blocking detail:** the sample app currently registers the Phase 1 ad-hoc
JSON blob, and the matcher now decodes versioned CBOR. Anyone pairing today's
`matcher.wasm` with today's sample app gets no matches at all — correctly, and
confusingly. Wiring `SirosBlobBuilder` through the SDK is what closes that,
and it has to land in the same change as a refreshed `matcher.wasm` asset.

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
