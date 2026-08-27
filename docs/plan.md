# Plan

Ordered so the riskiest unknown dies first. Phase 1 answers "can we replace the
stock matcher on a real device at all" before any effort goes into a DCQL
engine. Estimates are focused engineering time.

The full write-up, including the requirements analysis this came from, is at
<https://claude.ai/code/artifact/289c7f68-73f0-410b-ad44-17c5c20252c4>.

| Phase | Work | Estimate |
|---|---|---|
| 0 | Repo bootstrap under the settled licensing rules | ~2 days |
| 1 | Prove the matcher swap on hardware | ~1 week |
| 2 | Credential blob format and builder | ~1 week |
| 3 | The DCQL engine | ~2 weeks |
| 4 | Profile evaluator and the ZK path | ~1 week |
| 5 | Entry emission and display | ~3 days |
| 6 | Kotlin SDK integration | ~1 week |
| 7 | Swift parity and first release | ~3 days |

## Phase 0 — Bootstrap ✅

Workspace, BSD-2-Clause licence, the provenance rule in `CONTRIBUTING.md`
before any matching code exists, CI mirroring the house setup, and the
crates.io publishing path for `siros-dcql`.

**Done.** Outstanding: the crates.io owner account and `CARGO_REGISTRY_TOKEN`
secret, plus the `SONAR_TOKEN` secret — all require account access rather than
code.

## Phase 1 — Prove the swap on hardware

A matcher that reads the request and unconditionally emits one hardcoded entry,
plus the wasmtime test host implementing every import in `abi.rs`. Register it
from the Kotlin sample app in place of `OpenId4VpRegistry`, and confirm the
entry appears in a real picker on a real device.

Everything after this is incremental. If this does not work, nothing else
matters.

## Phase 2 — Blob format and builder

Versioned CBOR schema for credentials, display properties, icons and the match
profile. Encoder exposed through UniFFI so the Kotlin and Swift SDKs stop
hand-building registry payloads. Golden vectors committed so encoder and
matcher cannot drift apart.

## Phase 3 — The DCQL engine

Full DCQL 1.0 in `siros-dcql`: credential queries, claim paths, `claim_sets`,
claim `values` filters, `credential_sets` with required and optional options,
and combination enumeration with the single-member consolidation the picker
needs. Spec vectors, property tests, and differential runs against the oracle
in the shared test host.

Ends with `siros-dcql 0.1.0` published to crates.io.

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
