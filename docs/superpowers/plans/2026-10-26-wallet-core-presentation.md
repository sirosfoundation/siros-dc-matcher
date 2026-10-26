# SIROS Wallet Core: Presentation (Phase 1 and Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One Rust core answers every OpenID4VP presentation request a SIROS wallet receives, over redirects, the cloud engine and the Digital Credentials API, for SD-JWT VC, mdoc and `zkp_req`. Phase 1 turns a request and the wallet state into the consent display. Phase 2 turns the user's selection into the response the wallet sends.

**Architecture:** Each phase is a sans-IO function: it takes all of its inputs and returns either effects for the host (fetch, trust query, signature) or its result. Hosts keep the network, storage, keys, OS registration and the UI. The siros-dc-matcher crates are split by responsibility into codec, format, protocol, state, display, transaction-data and presentation crates. Four facades bind them: UniFFI for Kotlin and Swift, wasm-bindgen for the browser, a WASI module for Go under wazero, and `matcher.wasm` for the Android picker.

**Tech Stack:** Rust 1.99.1 (pinned), serde and serde_json, the strict CBOR codec of `siros-zkp-req` (moved to `siros-codec`), RustCrypto `p256`/`sha2`/`aes-gcm`, `zk-cred-longfellow` and `zk-cred-vega` through `siros-zkp-backend-*`, UniFFI 0.28, wasm-bindgen, wazero.

**Spec:** the normative texts below, plus the Design section of this document.
- OpenID4VP 1.0: §5 (Authorization Request), §6 (DCQL), §7 (claims path pointers), §8 (response: §8.1 `vp_token`, §8.3 encryption, §8.4 transaction data, §8.5 errors), Appendix A (DC API), Appendix B.2.6 (mdoc handovers), Appendix B.3 (SD-JWT VC).
- RFC 9901 (SD-JWT); SD-JWT VC draft as vc's `pkg/sdjwtvc` implements it (§5.6 array positions; type metadata `display` and `claims`).
- ISO/IEC 18013-5 (IssuerSigned, MSO, DeviceResponse, DeviceAuthentication).
- nym_auth rulebook at `e65861c`: `zkp_req.md` draft 0.1, `nym_auth_rulebook.md` 0.5, `systems/*`.
- SIROS private data spec 3.1 (`privatedata-spec`): §5A delivered secrets, §6 WalletStateContainer, §6.0 credential entry.
- OpenID4VP 1.0 transaction data: §5.1 (entry: `type`, `credential_ids`; the type defines the rest), §8.4 (the type defines what the presentation carries), §8.5 (`invalid_transaction_data`), and Appendix B.2.1, B.3.3 and B.3.3.1 (recommendations and one optional profile for type authors).
- EC TS12 v1.0.1 §1.2, §3.6, §4.2 and §4.3 (the four SCA transaction types).
- OpenID4VCI 1.0 `credential_metadata` (`display`, `claims`).

## Global Constraints

- Toolchain 1.99.1 (`rust-toolchain.toml`). Root workspace MSRV 1.82: it holds everything `matcher.wasm` links. The `wallet/` workspace has MSRV 1.95, because `zk-cred-*` are edition 2024.
- `matcher.wasm` ≤ 307,200 bytes (`WASM_SIZE_BUDGET`, `.github/workflows/ci.yml`).
- Every library crate: `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]`, `#![deny(missing_docs)]`, `#![deny(unsafe_code)]` (`android-credman-sys` excepted for its sys calls).
- No interior mutability in library code. UniFFI's `Arc` on exported objects is the only refcount.
- Collections: `rustc-hash` Fx maps and sets; `BTreeMap`/`BTreeSet` never; std `HashMap`/`HashSet` are in `clippy.toml` `disallowed-types`. Ordered output is a sorted `Vec`.
- Each unexpected state is an error where it is detected, with a stable `code()`. No `let _ =`, no default value after a failure.
- `CONTRIBUTING.md` §Provenance: Multipaz is an oracle; no Apache-2.0 expression enters.
- Tests: each names the failure it catches. Oracles are spec examples, vectors from another implementation, or values derived by hand. The default suite runs in under 10 s; real-proof tests are `#[ignore]` and run per merge.
- Text in docs, comments, commits and PRs follows the owner's writing rule (direct, no "X, not Y", nothing the context already says).
- Published coordinates stay: crates.io `siros-dcql`; Maven `org.siros:siros-dc-matcher` (AAR carrying `matcher.wasm`); XCFramework `siros_dc_matcher_ffi`; UniFFI namespace `siros_dc_matcher_ffi`.
- Work happens on `feat/wallet-core` in siros-dc-matcher, one PR per milestone; push after every commit. Every PR, here or in another repo, waits for the owner's go.
- eduID templates, configs and docs are never touched.

## Review Focus

1. A nested SD-JWT claim whose parent object is itself selectively disclosed: the presentation carries the parent's disclosure. Test in Task 2.2.
2. An unsigned DC API request: the KB-JWT `aud` is `origin:<origin>`, and the mdoc SessionTranscript uses `OpenID4VPDCAPIHandover` over that origin. Tests in Tasks 2.2 and 2.3.
3. A batch of one-time-use instances: each presentation uses one instance per credential, the least used one, and the presentation record names exactly that instance. Tests in Tasks 1.8 and 2.6.
4. An array element the issuer made a decoy or kept undisclosed: an index counts issued positions (SD-JWT VC §5.6). Tests in Tasks 1.2 and 1.4.
5. One request with a `zkp_req` query and a plain query: one consent, one `vp_token`, each query answered by its own builder. Test in Task 2.5.

---

## Design

### D1. Crate map

Root workspace `crates/` (MSRV 1.82):

| Crate | Comes from | Holds | In `matcher.wasm` |
|---|---|---|---|
| `siros-dcql` | unchanged | DCQL engine | yes |
| `siros-codec` | `siros-zkp-req/src/{cbor,base64url}.rs`, `siros-dc-matcher-core/src/base64url.rs` | strict CBOR, base64url | yes |
| `siros-wallet-state` | new | typed `S` of the private data container (privatedata §6) | no |
| `siros-sdjwt` | new | SD-JWT reading, disclosure selection, KB-JWT input | no |
| `siros-mdoc` | `siros-zkp-req-nym-auth/src/{mdoc,x509}.rs` (generic parts), `session.rs::device_message`, `checks.rs::es256_verifies` | IssuerSigned/MSO reading, DeviceResponse, DeviceAuthentication | no |
| `siros-credential` | new | typed credential model, claim tree, §7 pointer resolution | yes (projection subset) |
| `siros-display` | `siros-dc-matcher-core/src/purpose.rs`, `siros-dc-matcher-wasm/src/main.rs::zkp_req_rows` | display metadata, resolver, view types | yes (types) |
| `siros-oid4vp` | `siros-dc-matcher-core/src/request.rs`, `siros-zkp-req-nym-auth/src/{session,policy}.rs` (generic parts) | request intake, handovers, response encoding, JWE | yes (no `crypto` feature) |
| `siros-transaction-data` | port of siros-sdk-kotlin `transaction/*` | `transaction_data` decode, TS12 validation, hashes, display | no |
| `siros-zkp-req` | unchanged minus `cbor`/`base64url` | `zkp_req` protocol layer | yes |
| `siros-zkp-req-nym-auth` | shrinks | catalogue, systems, presenter, prover trait, verifier | catalogue and systems |
| `siros-presentation` | `siros-dc-matcher-core/src/{evaluator,profile}.rs` | planner, selection, builders orchestration | yes (`picker` feature) |
| `siros-picker-registration` | `siros-dc-matcher-core/src/db.rs` | picker registration projection and codec | yes |
| `android-credman-sys`, `android-credman` | `feat/android-credman-crates` | Credential Manager host ABI | yes |
| `siros-picker` | `siros-dc-matcher-wasm` (bin keeps the name `matcher`) | Android picker binary | is it |
| `siros-picker-testhost` | `siros-dc-matcher-testhost` | wasmtime host | dev |

Workspace `wallet/` (MSRV 1.95, was `proving/`):

| Crate | Comes from | Holds |
|---|---|---|
| `siros-zkp-backend-longfellow`, `siros-zkp-backend-vega` | unchanged | provers behind the existing pinned `load` |
| `siros-wallet` | new | the phase API with provers linked in |
| `siros-wallet-uniffi` | `siros-dc-matcher-ffi` (lib name `siros_dc_matcher_ffi`) | Kotlin and Swift |
| `siros-wallet-web` | `proving/siros-zkp-req-wasm` | browser, npm `@sirosfoundation/siros-wallet` |
| `siros-wallet-engine` | new | `wasm32-wasip1` module for the Go engine: intake and submission |
| `e2e` | unchanged | real-proof tests |

Deleted: `siros-dc-matcher-core`, `circuit_capabilities.rs` and its tests, the `MatchProfile` in the registration blob, `ciborium`.

### D2. Phases and effects

```rust
// siros-oid4vp: intake
pub fn start_redirect(uri: &str, wallet: &WalletMetadata) -> IntakeStep;
pub fn start_dc_api(envelope_json: &str, origin: &Origin) -> IntakeStep;
pub fn resume(state: IntakeState, input: IntakeInput) -> IntakeStep;
pub enum IntakeStep { Fetch { state: IntakeState, request: FetchRequest },
                      Trust { state: IntakeState, query: TrustQuery },
                      Ready(VerifiedRequest), Refused(RequestRefusal) }
pub enum IntakeInput { Fetched(FetchResponse), Trusted(TrustVerdict) }

// siros-presentation: phase 1 and phase 2
pub fn plan(input: &PlanInput<'_>) -> Result<Plan, Refusal>;
pub fn prepare(input: &PlanInput<'_>, selection: &Selection) -> Result<Prepared, Refusal>;
pub fn finish(input: &PlanInput<'_>, prepared: &PreparedState, signatures: &[Signature],
              provers: &dyn Provers, rng: &mut dyn CryptoRngCore) -> Result<Finished, Refusal>;
```

- `IntakeState` and `PreparedState` are plain serialisable records that the host carries between calls. Each call recomputes and checks everything; nothing is kept between calls (the pattern of the branch's `zkp_req` FFI).
- `FetchRequest { method, url, form: Vec<(String,String)>, max_bytes: u32, timeout_ms: u32 }`. The host fetches only `https` URLs on public addresses, follows no redirects, and enforces `max_bytes` and `timeout_ms` (the policy of Kotlin `SafeDocumentFetcher`).
- `TrustQuery { subject: TrustSubject, x5c: Vec<Vec<u8>>, did: Option<String> }`, where `TrustSubject` is either `ClientId(String)` or `Origin(String)`. `TrustVerdict { trusted: bool, verifier: Option<VerifierDisplay> }`. The host runs it against AuthZEN.
- `SignRequest { id: u32, kid: String, alg: JwsAlg, input: Vec<u8> }`. The host signs `input` with the key `kid` through wscd and returns `Signature { id, bytes }`.
- Provers run in-process in wallet builds through `siros-zkp-backend-*`. `secret_seed` therefore stays inside Rust from the container to the proof.

### D3. Who runs what

| Flow | Intake | `plan`/`prepare`/`finish` | Delivery |
|---|---|---|---|
| Redirect, web wallet | go-wallet-backend engine via `siros-wallet-engine` | browser via `siros-wallet-web` | engine POSTs the `Submission` |
| Redirect, native app | SDK via `siros-wallet-uniffi` (the "local engine" of `websocket-protocol-spec.md`) | SDK | SDK POSTs |
| DC API, native and web | client | client | the platform returns the `Submission` |
| Android picker | `siros-picker`, unverified request only | `siros-picker`, `picker` feature over the registration projection | entries to Credential Manager |

### D4. Go embeds a WASI module

go-wallet-backend builds with `CGO_ENABLED=0` (`Dockerfile`, `ci.yml`). The engine therefore runs `siros-wallet-engine.wasm` (`wasm32-wasip1`) under wazero. Requests and results cross as JSON through exported `alloc(len) -> ptr`, `call(op_ptr, op_len, in_ptr, in_len) -> u64` (packed ptr/len) and `free(ptr, len)`.

### D5. Rules in code

- The picker and the wallet ship in one AAR, so the matching rules version with the binary.
- The `MatchProfile` in the blob goes: protocol table, format table, meta rules, triggers and capability params. The rules become code in `siros-presentation`.
- Systems and their circuit pins stay as `feat/zkp-req-core` defines them (`NymAuthSystem::circuit_artifact()`, system rulebooks §8). Circuits load through the existing pinned `load`. A system is available when its circuits are loaded.

### D6. Wallet state input

- Phase 1 reads the decrypted `S` (privatedata §6): `S.credentials[]`, `S.presentations[]` and `S.keypairs[]`.
- Phase 2 returns a `NewPresentation` for the host's container code to append as a `new_presentation` event.
- Container crypto, reducers and merge stay in the platforms for this plan.

### D7. Display

- One resolver reads the OpenID4VCI `credential_metadata` (by `credentialIssuerIdentifier`, `credentialConfigurationId`) and SD-JWT VC type metadata (by `vct`), both from a host-supplied `DisplayCache`.
- It removes `auxiliary_data` before any merge (privatedata §5A.3).
- It outputs `DisplayValue`s that carry their type. The UI formats dates and numbers for its locale and renders everything else as given.

### D8. Selection semantics

- `claim_sets`: the first satisfiable set is disclosed in full (OpenID4VP §6.4.1). DCQL defines no per-claim toggle, so none exists.
- Required credential sets: each combination siros-dcql enumerates becomes an `Offer`.
- Optional credential sets: they become `OptionalSet` toggles on top of the chosen offer.
- A request whose sets are all optional: each option is its own `Offer`. Today it offers nothing, and vc's apigw issuance-auth query has exactly this shape.
- `multiple`: siros-dcql's current semantics stand.

### D9. Instances and validity

- Instance choice: per batch, take the instance named least often in `S.presentations[].usedCredentialIds`; on a tie, the lowest `instanceId`.
- Validity: a credential is offered when `not_before ≤ now < not_after`, taken from MSO `validityInfo` or SD-JWT `nbf`/`exp`.

### D10. Engine messages (OpenID4VP, API v2)

These replace `match_request`, `credential_selection` and `sign_request` for presentations:

```json
{"type":"presentation_request","flow_id":"…","request":<VerifiedRequest wire JSON>}
{"type":"presentation_response","flow_id":"…","submission":<Submission wire JSON>}
{"type":"flow_complete","flow_id":"…","redirect_uri":"…"}
```

### Open decision O1: `mso_mdoc_zk` / `zk_system_type`

This plan covers SD-JWT, mdoc and `zkp_req`. The Longfellow mdoc ZK path (`mso_mdoc_zk`, `zk_system_type`, `zk_required`) still has Kotlin and Swift provers, and vc `sunet/main` still verifies it. One of two outcomes is needed before Tasks 4.1–4.3 delete the platform matchers:
- **Retire:** delete it everywhere.
- **Carry:** port its matching and proving into the core, which adds tasks to M1 and M2.

---

## Milestones

| Milestone | Tasks | Ends with |
|---|---|---|
| M0 Restructure | 0.1–0.6 | one history, crates split, behaviour unchanged |
| M1 Phase 1 | 1.1–1.9 | `plan()`: request and state to `ConsentView` |
| M2 Phase 2 | 2.1–2.6 | `prepare()`/`finish()`: selection to `Submission` and `NewPresentation` |
| M3 Facades | 3.1–3.6 | UniFFI, web, Go, picker, one vector suite through all of them |
| M4 Adoption | 4.1–4.6 | Kotlin, Swift, web, engine and wrapper on the core; their copies deleted |

**Cycle for every task:**
- [ ] Write the listed tests and run them; they fail for the stated reason.
- [ ] Implement the listed interfaces.
- [ ] Run the task's gate commands, each with output redirected to a file and its exit status checked.
- [ ] Commit with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` and push.

---

## M0 Restructure

### Task 0.1: One history

**Files:** the merge of `feat/android-credman-crates` (`3b47d90`) and `feat/zkp-req-core` (`25b4a02`). The conflicts are `.github/workflows/ci.yml`, `CHANGELOG.md`, `Cargo.toml`, `clippy.toml`, `crates/siros-dc-matcher-core/src/zkp_req.rs` and `zkp_req_response.rs` (deleted, as `feat/zkp-req-core` does), and `crates/siros-dc-matcher-wasm/src/main.rs` (keep credman's emission and use the branch's `ZkpReqSelection`).

**Sequence:** PR `feat/android-credman-crates` → main, then PR `feat/zkp-req-core` → main, each after the owner's go. `feat/wallet-core` starts from the result.

**Gate:**
- `cargo test --locked --workspace --all-features` and `cd proving && cargo test --locked` both exit 0.
- `scripts/check_matcher_abi.py` passes.
- `matcher.wasm` ≤ 307,200 B; record the size.
- The credman G2 harness transcript equals the one at `3b47d90` for every case without `zkp_req`.
- `cd proving && cargo test --release -- --ignored` passes 2/2.

### Task 0.2: `siros-codec`

**Files:**
- Create `crates/siros-codec/{Cargo.toml,src/lib.rs,src/cbor.rs,src/base64url.rs}`, moved from `crates/siros-zkp-req/src/{cbor,base64url}.rs`.
- Delete `crates/siros-dc-matcher-core/src/base64url.rs`.
- Point every user at `siros_codec` (`siros-zkp-req`, `siros-zkp-req-nym-auth`, core's `request.rs`), with no re-export.

**Interfaces:**
- `siros_codec::cbor::{Value, decode(&[u8]) -> Result<Value, DecodeError>, Value::encode(&self) -> Vec<u8>}` and `siros_codec::base64url::{decode(&str) -> Option<Vec<u8>>, encode(&[u8]) -> String}`, with the signatures the moved files already have.
- New `siros_codec::hash::HashAlg { Sha256, Sha384, Sha512 }` with `from_iana(&str) -> Option<HashAlg>` (`sha-256`, `sha-384`, `sha-512`) and `digest(self, &[u8]) -> Vec<u8>` (`sha2`).
- New `siros_codec::jose::JwsAlg { Es256, Es384, Es512 }` with `name(self) -> &'static str` and `from_name(&str) -> Option<JwsAlg>`.

**Tests:** the moved unit tests. One added test, `base64url_encode_inverts_decode` over the RFC 4648 §10 vectors re-encoded without padding.

**Gate:**
- `grep -rn 'fn decode(input: &str) -> Option<Vec<u8>>' crates` gives 1 line.
- `matcher.wasm` size ≤ Task 0.1's size.

### Task 0.3: `siros-oid4vp` from moved code

**Files:**
- Create `crates/siros-oid4vp/src/{lib.rs,dc_api.rs,handover.rs,jwk.rs}`.
- `dc_api.rs` takes core `request.rs`: `NoQuery`, `Shape`, `first_supported_*`, `extract_*`, `diagnose`, `RequestContext`.
- `handover.rs` takes nym-auth `session.rs`: `Handover`, `HandoverInvalid`, `session_transcript`.
- `jwk.rs` takes `ec_jwk_thumbprint`.
- The generic parts of nym-auth `policy.rs` (`Channel`, `Endpoint`, `CheckedRequest`) move to `lib.rs`.
- nym-auth keeps `policy::check_nym_auth(request: &CheckedRequest, signed: bool) -> Result<(), PolicyRule>`: signed only, `direct_post.jwt` or `direct_post.cwt` over redirects, `dc_api.jwt` over the DC API, `jwks` present.
- Move `crates/siros-dc-matcher-core/tests/request_shapes.rs` to `crates/siros-oid4vp/tests/`.

**Interfaces:**
- `Handover::dc_api(origin: &str, nonce: &str, jwk_thumbprint: Option<&[u8; 32]>) -> Handover`.
- `Handover::redirect(client_id: &str, nonce: &str, jwk_thumbprint: Option<&[u8; 32]>, response_uri: &str) -> Handover`.
- `None` encodes CBOR `null` (OpenID4VP B.2.6, unencrypted responses).

**Tests:**
- `request_shapes.rs`, unchanged assertions.
- `handover_without_encryption_encodes_null`: decoding `cbor([origin, nonce, null])` inside the digest preimage gives `Value::Null` at index 2.

**Gate:**
- The nym-auth suites (`flow.rs`, `known_answers.rs`, `readdit.rs`) pass.
- For the encrypted case, the Handover bytes before and after the move are byte-identical over the readdit vectors. Run this comparison once, as a refactor check.

### Task 0.4: `siros-mdoc` from moved code

**Files:**
- Create `crates/siros-mdoc/src/{lib.rs,issuer_signed.rs,mso.rs,device.rs,x509.rs}` with feature `crypto` (`p256`, `x509-cert`, `der`).
- `issuer_signed.rs` and `mso.rs` take nym-auth `mdoc.rs` `envelope`, `read_issuer_auth`, `read_mso` and `read_elements`.
- `device.rs` takes `session::device_message` and `challenge_digest`.
- `x509.rs` takes nym-auth `x509.rs`.
- `checks::es256_verifies` moves to `siros_mdoc::es256_verifies`.
- nym-auth's `NymAuthMdoc` becomes a view built from `siros_mdoc::Document`.

**Interfaces:**
- `siros_mdoc::read(data: &str) -> Result<Document, MdocError>`. `data` is base64url without padding of an `IssuerSigned`, a `Document`, or a `DeviceResponse` with one document, as nym-auth reads it today.
- `Document { doc_type: String, name_spaces: Vec<NameSpace>, issuer_auth: Vec<u8>, mso: Mso }`.
- `NameSpace { name: String, items: Vec<IssuerSignedItem> }`.
- `IssuerSignedItem { digest_id: u64, element_identifier: String, element_value: siros_codec::cbor::Value, encoded: Vec<u8> }`. `encoded` holds the tag-24 bytes verbatim.
- `Mso { doc_type: String, validity: Validity, device_key: CoseKey, value_digests: … }`.

**Tests:** the moved nym-auth tests. `reads_annex_d_issuer_signed`: the ISO/IEC 18013-5 Annex D.4.1.2 DeviceResponse example decodes to doc type `org.iso.18013.5.1.mDL`, `family_name` = `"Doe"`, and the item count of the annex's table.

**Gate:**
- `grep -rn 'fn read_mso\|fn read_issuer_auth' crates` shows only `siros-mdoc`.
- `cargo test -p siros-zkp-req-nym-auth` exits 0.

### Task 0.5: `siros-picker-registration`

**Files:**
- Create `crates/siros-picker-registration/src/{lib.rs,codec.rs}`, moved from core `db.rs`, encoding through `siros-codec`. Remove `ciborium` and `serde_bytes`.
- Move `crates/siros-dc-matcher-core/tests/golden_blob.rs` and its `golden/` directory.

**Interfaces:**
- `CredentialDatabase::to_cbor(&self) -> Vec<u8>`.
- `CredentialDatabase::from_cbor(&[u8]) -> Result<CredentialDatabase, DecodeError>`.
- `VERSION` stays 1.

**Tests:** `golden_blob.rs`, unchanged. It is the gate that ciborium's output and the strict codec's output are identical bytes.

**Gate:** `cargo tree -i ciborium` lists nothing.

### Task 0.6: Retire `siros-dc-matcher-core`; rename and regroup

**Files:**
- `evaluator.rs` and `profile.rs` → `crates/siros-presentation/src/{policy.rs,profile.rs}` as they are.
- `purpose.rs` → `crates/siros-display/src/purpose.rs`.
- `sink.rs::Entry` → `crates/siros-picker/src/entry.rs`.
- `fixtures.rs` → the `test-fixtures` features of `siros-presentation` and `siros-picker-registration`.
- Delete `circuit_capabilities.rs` and `tests/circuit_capabilities.rs` (D5).
- `git mv` `crates/siros-dc-matcher-wasm` → `crates/siros-picker` and `crates/siros-dc-matcher-testhost` → `crates/siros-picker-testhost`.
- `git mv proving wallet`; `crates/siros-dc-matcher-ffi` → `wallet/siros-wallet-uniffi` (`[lib] name = "siros_dc_matcher_ffi"`); `proving/siros-zkp-req-wasm` → `wallet/siros-wallet-web`.
- Update `Makefile` targets (`matcher`, `aar`, `xcframework`, `bindings`, `check-bindings`) and the CI paths.
- `wallet/Cargo.toml` adds the path dependencies on the root crates.

**Tests:** the moved suites.

**Gate:**
- `grep -rn siros_dc_matcher_core` gives 0.
- `make check-bindings` passes with no regeneration (same exported API).
- The G2 harness transcript equals Task 0.1's.
- `matcher.wasm` ≤ Task 0.2's size.
- Both workspaces' tests exit 0.

---

## M1 Phase 1: request and wallet state to display

### Task 1.1: `siros-wallet-state`

**Files:** `crates/siros-wallet-state/src/{lib.rs,credential.rs,presentation.rs,keypair.rs}`; `tests/privatedata_vectors.rs`; `tests/vectors/` copied from privatedata-spec `test-vectors/` with a `SOURCE` file pinning `0c7405a`.

**Interfaces:**
- `WalletState::from_plaintext(json: &str) -> Result<WalletState, StateError>`. It reads `S` of a WalletStateContainer plaintext; `schemaVersion` must be 3 or 4, an absent value meaning 1.
- `WalletState { credentials: Vec<CredentialEntry>, presentations: Vec<PresentationEntry>, keypairs: Vec<KeypairRef> }`.
- `CredentialEntry { credential_id: u64, data: String, format: String, kid: String, instance_id: u64, batch_id: u64, issuer: String, configuration_id: String, metadata: Vec<MetadataEntry> }`.
- `MetadataEntry { kind: String, value: serde_json::Value }`; the spec member is `type`.
- `PresentationEntry { presentation_id: u64, transaction_id: u64, used_credential_ids: Vec<u64>, timestamp_seconds: i64, audience: String }`.
- `KeypairRef { kid: String }`.
- `NewPresentation { presentation_id: u64, transaction_id: u64, data: String, used_credential_ids: Vec<u64>, timestamp_seconds: i64, audience: String }` (the fields of wallet-frontend `WalletSessionEventNewPresentation`).
- `StateError::{UnsupportedVersion(u64), Malformed(&'static str)}`, each with `code()`.

**Tests:**
- `reads_every_plaintext_fixture`: each fixture's `S` gives as many credentials as the fixture lists, and every `credential_id` of `usedCredentialIds` exists.
- `refuses_unknown_schema_version`: `schemaVersion: 5` → `UnsupportedVersion(5)`.
- `credential_id_beyond_i32`: `4294967295` round-trips as a `u64`.

### Task 1.2: `siros-sdjwt` reading

**Files:** `crates/siros-sdjwt/src/{lib.rs,parse.rs,tree.rs}`; `tests/rfc9901.rs`; `tests/vectors/rfc9901/` holding the RFC 9901 Appendix A examples, copied verbatim.

**Interfaces:**
- `parse(compact: &str) -> Result<SdJwt, SdJwtError>`.
- `SdJwt { issuer_jwt: String, payload: serde_json::Value, disclosures: Vec<Disclosure>, sd_alg: HashAlg }`.
- `Disclosure { encoded: String, digest: String, name: Option<String>, value: serde_json::Value }`.
- `SdJwt::tree(&self) -> Result<siros_credential::Node, SdJwtError>`. It resolves `_sd` and array `{"...": digest}` entries. A digest with no disclosure becomes `Node::Withheld` at its array position. An undisclosed object member is absent from the tree.
- `SdJwtError` codes:

| Code | Rule |
|---|---|
| `duplicate_digest` | RFC 9901 §7.1 |
| `unreferenced_disclosure` | §7.1 |
| `reserved_claim_name` | `_sd` or `...` as a name |
| `disclosure_shape` | malformed disclosure |
| `unsupported_sd_alg` | `sd_alg` |
| `malformed_jwt` | issuer JWT |

**Tests:**
- `appendix_a_examples_resolve`: each example's fully disclosed payload equals the RFC's processed payload.
- `decoy_in_array_keeps_position`: `["DE", {"...": decoy}, "US"]` gives a tree whose index 2 is `"US"` and whose index 1 is `Withheld`.
- One test per error code above.

### Task 1.3: `siros-mdoc` claim tree

**Files:** `crates/siros-mdoc/src/tree.rs`.

**Interfaces:** `Document::tree(&self) -> siros_credential::Node`. The root is an object of namespaces; each namespace is an object of elements; each element carries `DisclosureHandle::Mdoc { namespace, element }`. Value mapping:

| CBOR | `ClaimValue` |
|---|---|
| tag 1004 | `FullDate` |
| tag 0 | `DateTime` |
| bstr | `Bytes` |
| map | `Object`, keys sorted |
| array | `Array` |

**Tests:** `annex_d_values_typed`: Annex D.4.1.2 `birth_date` → `FullDate` with the annex's date, and `portrait` → `Bytes` with the annex's length.

### Task 1.4: `siros-credential`

**Files:** `crates/siros-credential/src/{lib.rs,node.rs,pointer.rs,credential.rs,batch.rs}`.

**Interfaces:**
- `enum Node { Present { value: ClaimValue, handle: Option<DisclosureHandle> }, Withheld }`.
- `enum ClaimValue { Null, Bool(bool), Integer(i64), Number(f64), Text(String), Bytes(Vec<u8>), FullDate(Date), DateTime(i64), Array(Vec<Node>), Object(Vec<(String, Node)>) }`.
- `enum DisclosureHandle { SdJwt { digest: String }, Mdoc { namespace: String, element: String } }`.
- `struct Pointer(pub Vec<siros_dcql::PathComponent>)`: a claims path pointer (OpenID4VP §7).
- `Credential { entry: EntryRef, format: Format, kind: CredentialType, issuer: String, configuration_id: String, claims: Node, validity: Validity, kid: String, auxiliary: Vec<serde_json::Value> }`.
- `EntryRef { credential_id: u64, batch_id: u64, instance_id: u64 }`.
- `enum CredentialType { Vct(String), DocType(String) }`.
- `Credential::read(entry: &CredentialEntry) -> Result<Credential, ReadError>` dispatches on `format`: `dc+sd-jwt` to `siros_sdjwt`, `mso_mdoc` to `siros_mdoc`. Any other format → `ReadError::UnsupportedFormat`. It sits behind feature `state`; the picker builds without it.
- `impl siros_dcql::Credential for Credential`. `claim(path)` follows OpenID4VP §7.1: `null` gives the present elements, an index counts every position including `Withheld`, and an index on `Withheld` → `PathError::Empty`. `values` comparison maps `FullDate` to `"YYYY-MM-DD"`.
- `fn batches<'a>(credentials: &'a [Credential]) -> Vec<Batch<'a>>`.
- `Batch::least_used(&self, presentations: &[PresentationEntry]) -> &Credential` (D9).

**Tests:**
- `section_7_3_examples`: the claims-path examples of OpenID4VP §7.3 over its example document give the values the section states.
- `index_counts_withheld_positions`: Review Focus 4.
- `least_used_instance_then_lowest_id`: instances 0, 1 and 2 used 2, 1 and 1 times → instance 1.

**Gate:** remove the "Known limitation" text in `evaluator.rs`'s successor; `grep -rn 'as_key).collect' crates/siros-presentation` gives 0.

### Task 1.5: `siros-display`

**Files:** `crates/siros-display/src/{lib.rs,metadata.rs,resolve.rs,value.rs,purpose.rs,zkp.rs}`; `tests/strip.rs`.

**Interfaces:**
- `DisplayCache { issuer: Vec<IssuerEntry>, types: Vec<TypeEntry> }`.
- `IssuerEntry { issuer: String, configuration_id: String, credential_metadata: serde_json::Value }`.
- `TypeEntry { vct: String, type_metadata: serde_json::Value }`.
- `strip_auxiliary_data(credential_metadata: &mut serde_json::Value)`.
- `struct Locale(String)`: a BCP 47 tag, in the user's order of preference.
- `card(credential: &Credential, cache: &DisplayCache, locales: &[Locale]) -> CredentialCard`, where `CredentialCard { title: String, subtitle: Option<String>, logo: Option<Image>, background_color: Option<String>, text_color: Option<String> }` and `Image { uri: String, alt_text: Option<String> }`. The OpenID4VCI `display` wins over type metadata `display` for the same locale.
- `claim_rows(credential: &Credential, paths: &[Pointer], cache: &DisplayCache, locales: &[Locale]) -> Vec<ClaimRow>`, where `ClaimRow { path: Pointer, label: String, value: DisplayValue }`.
- `enum DisplayValue { Text(String), Bool(bool), Integer(i64), Number(f64), Date { year: i32, month: u8, day: u8 }, DateTime(i64), Image { media_type: String, bytes: Vec<u8> }, Bytes { len: u32 }, List(Vec<DisplayValue>), Group(Vec<ClaimRow>) }`.
- `negotiate(available: &[&str], wanted: &[Locale]) -> Option<usize>`: exact match first, then the primary language subtag, then the first entry.
- `purpose::display` and `purpose::line`, moved.
- `zkp::statement_rows(query: &siros_zkp_req::ZkpReqQuery, option: &siros_zkp_req::QueryOption) -> Vec<(String, String)>`, moved from the picker's `zkp_req_rows`.

**Tests:**
- `strip_vector`: privatedata vector `delivered-secret-strip-001` gives its expected merged object.
- `negotiate_table`: `fr-CA` against `[en, fr]` → `fr`; `de` against `[en, fr]` → `en`; `en-GB` against `[en-GB, en]` → `en-GB`.
- `bytes_never_display_content`: `ClaimValue::Bytes(64 bytes)` → `DisplayValue::Bytes { len: 64 }`. Images come only from a claim whose type metadata marks it as an image (`portrait` of an mdoc mDL).

### Task 1.6: `siros-oid4vp` intake

**Files:** `crates/siros-oid4vp/src/{intake.rs,request.rs,client_id.rs,jar.rs,wallet_metadata.rs,error.rs}` with feature `crypto` for `jar.rs`; `tests/intake.rs`; `tests/vectors/oid4vp/` holding the request examples of OpenID4VP 1.0 §5 and Appendix A.

**Interfaces:**
- D2 `start_redirect`, `start_dc_api`, `resume`, `IntakeStep`.
- `VerifiedRequest { channel: VerifiedChannel, client: ClientId, nonce: String, state: Option<String>, response: ResponseTarget, dcql: serde_json::Value, client_metadata: serde_json::Value, transaction_data: Vec<String>, verifier: VerifierView }`.
- `enum VerifiedChannel { Redirect, DcApi { origin: String, signed: bool } }`.
- `ClientId { prefix: ClientIdPrefix, value: String }`, `enum ClientIdPrefix { RedirectUri, X509SanDns, X509Hash, DecentralizedIdentifier, VerifierAttestation, OpenidFederation, Origin }`.
- `ResponseTarget { mode: ResponseMode, uri: Option<String>, encryption: Option<EncryptionKey> }`, `enum ResponseMode { DirectPost, DirectPostJwt, DirectPostCwt, DcApi, DcApiJwt }`.
- `EncryptionKey { jwk: serde_json::Value, kid: Option<String>, enc: JweEnc }`. `enc` is the first of the request's `encrypted_response_enc_values_supported` that the core implements (`A128GCM`, `A256GCM`), and `A128GCM` when the list is absent.
- `VerifierView { client_id: String, display: Option<VerifierDisplay>, trusted: bool }`, `VerifierDisplay { name: Option<String>, logo: Option<Image> }`.
- `FetchResponse { status: u16, content_type: Option<String>, body: Vec<u8> }`.
- `RequestRefusal { code: ErrorCode, rule: &'static str, reply: Option<ReplyTarget> }`, where `ErrorCode` is one of the OpenID4VP §8.5 codes: `invalid_request`, `access_denied`, `vp_formats_not_supported`, `invalid_request_uri_method`, `invalid_transaction_data`, `wallet_unavailable`. `reply` is present only when a response URI is known and trusted.
- `ReplyTarget { response_uri: String, state: Option<String> }`.
- `WalletMetadata`: the `wallet_metadata` posted with `request_uri_method=post` (OpenID4VP §5.10). Its `vp_formats_supported` lists `dc+sd-jwt`, `mso_mdoc`, and `zkp_req` with the loaded systems and backends.

**Rules, one refusal fixture each, in one table test `refusal_rules`:**
1. The request object `typ` differs from `oauth-authz-req+jwt`.
2. JWS `alg` is `none` or outside `{ES256, ES384, ES512}`.
3. The outer `client_id` differs from the request object's `client_id`.
4. `x509_san_dns`: no `dNSName` SAN of the `x5c` leaf equals the value.
5. `x509_hash`: base64url(SHA-256(leaf DER)) differs from the value.
6. `redirect_uri` prefix with a signed request; or a `redirect_uri` value that differs from `response_uri`.
7. `response_mode` is unknown, or does not belong to the channel: `direct_post*` over redirects, `dc_api*` over the DC API.
8. `direct_post*` without `response_uri`.
9. A signed DC API request whose `expected_origins` lacks the origin.
10. An unsigned DC API request that carries `client_id`.
11. `nonce` is absent or empty.
12. Both `dcql_query` and `scope` are absent, or both are present.
13. An encrypted response mode without a key in `client_metadata.jwks`.
14. `TrustVerdict.trusted == false` → `access_denied`.
15. `openid4vp-v1-multisigned`: the first signature whose `client_id` prefix is supported, and that verifies under that prefix, gives `client`. A request where no signature qualifies is refused.

**Tests:**
- `refusal_rules`.
- `spec_examples_verify`: each §5 and Appendix A example reaches `Ready`, or `Trust` → `Ready` with a trusted verdict, and has the `client_id`, `nonce` and `response_mode` the example states.
- `request_uri_post_carries_wallet_metadata`: the `Fetch` form holds `wallet_metadata` and `wallet_nonce`, and the `Ready` request's `wallet_nonce` must equal it (otherwise rule `wallet_nonce_mismatch`).

### Task 1.7: `siros-transaction-data`

**Normative structure (OpenID4VP 1.0):**
- §5.1: each entry is a base64url JSON object. The spec defines `type` and `credential_ids`. The type defines every other member, and which credentials can authorize it. When `credential_ids` has several elements, exactly one of the referenced credentials carries the transaction.
- §8.4: the presentation carries a representation of, or reference to, the data, in a way the type defines.
- §8.5: `invalid_transaction_data` covers seven conditions:
  - an unknown or unsupported type;
  - unknown fields;
  - fields of the wrong type;
  - invalid values;
  - missing required fields;
  - `credential_ids` not matching;
  - referenced credentials not available.
- Appendix B holds RECOMMENDATIONS for type authors; types opt into them:
  - B.2.1 (mdoc): a `DeviceSigned` data element per type. An element the MSO's `KeyAuthorizations` do not authorize makes the type unsupported.
  - B.3.3 (SD-JWT VC): a top-level KB-JWT claim per type. Holder binding is required.
  - B.3.3.1: one profile a type may adopt. The request member `transaction_data_hashes_alg` is optional with default `sha-256`. The KB-JWT claims are `transaction_data_hashes` (base64url hash of each entry's string exactly as received) and `transaction_data_hashes_alg` (present when the request carried it).

**Types shipped:** the four of EC TS12 v1.0.1 §4.3: `urn:eudi:sca:payment:1`, `urn:eudi:sca:login_risk_transaction:1`, `urn:eudi:sca:account_access:1`, `urn:eudi:sca:emandate:1`. Per TS12:
- they are for SD-JWT VC only (§1.2);
- §4.2 requires `transaction_data_hashes_alg` and `payload`, and every payload requires `transaction_id`;
- §3.6 requires `jti`, `response_mode` and `amr` in the KB-JWT;
- `transaction_data_hashes` follows B.3.3.1.

The behaviour of siros-sdk-kotlin `sdk/wallet/.../transaction/*.kt` and its tests is the reference for the TS12 validation and display rules. The rules are ported; the expression is our own.

**Files:** `crates/siros-transaction-data/src/{lib.rs,entry.rs,types.rs,profile_b331.rs,ts12/{mod.rs,schemas/,display.rs,metadata.rs}}`. `ts12/schemas/` holds the four TS12 payload schemas verbatim with Kotlin `Ts12Schemas.kt`'s SHA-256 pins. Add `tests/vectors/transaction-data-hashes.json`, copied from Kotlin `src/test/resources/ts12/` with a `SOURCE` pin.

**Interfaces:**
- `decode(entries: &[String], query_ids: &[&str]) -> Result<Vec<Entry>, TxRefusal>`. Each entry is base64url of a JSON object with no duplicate keys, `type` a string, and `credential_ids` a non-empty subset of `query_ids`.
- `Entry { index: usize, raw: String, kind: String, credential_ids: Vec<String>, members: serde_json::Map<String, serde_json::Value> }`. `members` holds every member except `type` and `credential_ids`.
- The type trait:

```rust
pub trait TransactionType {
    fn id(&self) -> &'static str;
    fn parse(&self, entry: &Entry, metadata: &TxMetadata) -> Result<Parsed, TxRefusal>;
    fn authorizes(&self, credential: &Credential) -> bool;
    fn display(&self, parsed: &Parsed, locales: &[Locale]) -> Result<TransactionView, TxRefusal>;
    fn bind(&self, parsed: &Parsed, format: &Format) -> Result<Vec<Binding>, TxRefusal>;
}
```

  Each method's job:
  - `parse` enforces the type's members (unknown, wrong type, invalid, missing).
  - `authorizes` says which credentials the type document allows.
  - `bind` says what the presentation carries for this entry.
- `Binding` has three variants:
  - `KbJwtClaim { name: String, value: BindingValue }`;
  - `HashesProfile` (B.3.3.1);
  - `DeviceSigned { namespace: String, element: String, value: siros_codec::cbor::Value }`.
- `BindingValue` has three variants:
  - `Json(serde_json::Value)`;
  - `FreshJti` (32 random bytes, base64url);
  - `ResponseMode`, `Amr` (filled in by the builder from the request and from the signing key).
- `profile_b331::claims(entries: &[&Entry]) -> Result<Vec<(String, serde_json::Value)>, TxRefusal>` covers the entries bound to one credential.
  - The algorithm is the first that every entry lists in `transaction_data_hashes_alg` and that `HashAlg` implements; `sha-256` when no entry carries the member.
  - It gives `transaction_data_hashes` in entry order, plus `transaction_data_hashes_alg` when any entry carried it.
- `Registry::ts12() -> Registry` with the four types. `Registry::get(&self, kind: &str) -> Option<&dyn TransactionType>`.
- `TxMetadata { type_metadata: Vec<(String, serde_json::Value)>, documents: Vec<(String, Vec<u8>)> }`, keyed by `vct` and by URL. The host fetches them through `FetchRequest`s with the D2 constraints.
- `TransactionView { title: String, rows: Vec<(String, String)>, affirmative_action_label: String }`.
- `TxRefusal { rule: &'static str }`, mapped to `ErrorCode::InvalidTransactionData`.
- TS12 display fails closed when a localised parameter name or `affirmative_action_label` is missing. It also refuses a string with control, format or bidi characters, or longer than Kotlin `DisplayText`'s cap.

**Planner rules (implemented in Task 1.8):**
- An entry binds to exactly one member. That member is the first query id of `credential_ids` that the offer answers with a credential the type `authorizes`.
- An offer that cannot bind every entry is dropped.
- If no offer remains, the request is refused with `invalid_transaction_data` ("referenced credentials not available").
- An SD-JWT member whose query sets `require_cryptographic_holder_binding: false` refuses its bindings (B.3.3).
- A `DeviceSigned` binding whose element the MSO `KeyAuthorizations` do not authorize is refused (B.2.1).

**Tests:**
- `section_8_5_conditions`: one fixture per §8.5 condition.
- `hashes_profile_vectors`: the Kotlin JSON. Each hash is over the entry's string as received.
- `two_credential_ids_bind_once`: an entry with `credential_ids: [a, b]`, and an offer answering both, binds to `a` only.
- `holder_binding_false_refused` (B.3.3).
- `unauthorized_device_signed_refused` (B.2.1), through a test-fixture type that binds to mdoc.
- `ts12_kb_claims`: a payment entry gives the claims `transaction_data_hashes`, `transaction_data_hashes_alg`, `jti`, `response_mode` and `amr`.
- `ts12_schemas_pinned`.

### Task 1.8: `siros-presentation` planner

**Files:** `crates/siros-presentation/src/{lib.rs,rules.rs,zkp.rs,offers.rs,plan.rs}`; delete `profile.rs` and the profile half of `policy.rs` from Task 0.6. The picker reads a v1 blob into `siros_credential::Credential` (string values as `Text`) until Task 3.3.

**Interfaces:**
- `PlanInput<'a> { request: RequestView<'a>, credentials: &'a [Credential], presentations: &'a [PresentationEntry], display: &'a DisplayCache, systems: &'a [AvailableSystem], keys: &'a [KeyInfo], transactions: &'a TxMetadata, locales: &'a [Locale], now: i64 }`.
- `KeyInfo { kid: String, amr: Vec<String> }`: the authentication factors the host's key applies when it signs, which TS12's `amr` reports.
- `enum RequestView<'a> { Verified(&'a VerifiedRequest), Unverified(&'a RequestContext) }`; the second exists in the `picker` feature only.
- `AvailableSystem { system: NymAuthSystem, backend: &'static str }`.
- `Plan { digest: [u8; 32], offers: Vec<Offer>, optional_sets: Vec<OptionalSet>, consent: ConsentView }`.
- `Offer { id: u32, members: Vec<Member> }`.
- `Member { query_id: String, credential: EntryRef, answer: Answer, transactions: Vec<usize> }`. `transactions` lists the `Entry.index` values bound to this member.
- `enum Answer { SdJwt { paths: Vec<Pointer> }, Mdoc { elements: Vec<(String, String)> }, ZkpReq(ZkpAnswer) }`.
- `ZkpAnswer { system: NymAuthSystem, proof_backend: String, req_set: Option<usize>, items: Vec<usize> }`.
- `OptionalSet { index: usize, options: Vec<Vec<Member>> }`.
- `Refusal { code: ErrorCode, rule: &'static str }`.
- `digest`: SHA-256 over the CBOR array `[request digest, credential ids in input order, now]`.

**Rules (code):**
- Formats: `mso_mdoc`→`mso_mdoc`, `dc+sd-jwt`→`dc+sd-jwt`, `zkp_req`→its `meta.source_format`.
- `meta.doctype_value` equals the DocType; `meta.vct_values` contains the vct.
- `has_cryptographic_holder_binding()` is true when `kid` is non-empty.
- nym_auth non-disclosure (`NYM_AUTH_UNDISCLOSABLE`, any non-`zkp_req` query).
- Validity (D9).
- `zkp_req`: `siros_zkp_req::ZkpReqQuery::parse` → `siros_zkp_req_nym_auth::catalogue::validate` → per option in the verifier's order, the first `AvailableSystem` that `usable_backend` accepts. Then the presenter's credential checks run (`checks::check` with anchors and `proof_time = now`), and `opens_ssc` with the seed from `auxiliary` (privatedata §5A.2). This replaces the separate `presenter::match_query` selection.
- Offers and optional sets: D8.
- Instance: D9, one per batch per member.
- Transaction data: the planner rules of Task 1.7.

**Tests:**
- `dcql_spec_vectors_plan`: siros-dcql's `spec_vectors` over the shared credential fixtures give the offers the vectors expect.
- `nym_auth_secret_never_offered`: a `dc+sd-jwt` or `mso_mdoc` query for `ssc` → no offer.
- `expired_not_offered`.
- `zkp_req_refusal_codes`: the nym-auth `refusals.rs` table through `plan`, same codes.
- `all_optional_sets_offer_each_option` (D8).
- `seed_not_opening_ssc_refused`.
- `one_instance_per_batch` (Review Focus 3).

### Task 1.9: `ConsentView` and `plan()`

**Files:** `crates/siros-presentation/src/consent.rs`.

**Interfaces:**
- `ConsentView { verifier: VerifierView, purposes: Vec<String>, offers: Vec<OfferView>, optional_sets: Vec<OptionalSetView>, transactions: Vec<TransactionView> }`.
- `OfferView { offer: u32, credentials: Vec<CredentialConsent> }`.
- `CredentialConsent { query_id: String, card: CredentialCard, disclosed: Vec<ClaimRow>, statements: Vec<(String, String)> }`.
- `OptionalSetView { index: usize, options: Vec<Vec<CredentialConsent>> }`.

**Tests:**
- `rows_equal_disclosure`: for every offer of `dcql_spec_vectors_plan`, the set of `disclosed[].path` equals the member's `Answer` paths.
- `no_secret_in_view`: the serialised `ConsentView` of a nym_auth plan contains neither the seed's base64url `opening` nor the hex of `secret_seed`.

**Gate (M1):**
- `cargo test --workspace` exits 0, in under 10 s on a quiet machine (check the load first).
- `matcher.wasm` ≤ budget.
- PR `feat/wallet-core` M1 → main after the owner's go.

---

## M2 Phase 2: selection to response

### Task 2.1: Selection and `prepare`/`finish`

**Files:** `crates/siros-presentation/src/{select.rs,respond.rs}`.

**Interfaces:**
- `Selection { plan_digest: [u8; 32], offer: u32, optional: Vec<(usize, usize)> }`, as `(set index, option index)` pairs.
- `prepare(input, selection) -> Result<Prepared, Refusal>`, `Prepared { state: PreparedState, signs: Vec<SignRequest> }`.
- `PreparedState { plan_digest: [u8; 32], selection: Selection, iat: i64, builders: Vec<BuilderState> }`. One `BuilderState` per member holds what `finish` needs: the SD-JWT presentation and its sign id; the mdoc document index and its sign id; or the nym-auth `Prepared` encoding and its sign id.
- `finish(...)` (D2) → `Finished { submission: Submission, record: NewPresentation }`.

**Tests:** `selection_refusals`, one row per rule: unknown `offer`; optional set or option out of range; `plan_digest` differs from a recomputed plan; a signature id missing or duplicated; a signature for an unknown id.

### Task 2.2: SD-JWT presentation

**Files:** `crates/siros-sdjwt/src/{select.rs,kb.rs}`.

**Interfaces:**
- `SdJwt::select(&self, paths: &[Pointer]) -> Result<Vec<&Disclosure>, SelectError>`. It returns the disclosures of every node on each path, parents included, each once and in the order of `disclosures`. An empty `paths` gives an empty selection.
- `presentation(&self, selected: &[&Disclosure]) -> String` gives `<issuer-jwt>~<d1>~…~`.
- `kb_signing_input(presentation: &str, aud: &str, nonce: &str, iat: i64, alg: JwsAlg, extra: &[(String, serde_json::Value)]) -> Result<Vec<u8>, SelectError>`.
  - The header is `{"typ":"kb+jwt","alg":…}`.
  - The payload is `{iat, aud, nonce, sd_hash}` plus `extra`. `extra` holds the claims the member's transaction bindings resolve to (Task 1.7: `KbJwtClaim`, `profile_b331::claims`, with `FreshJti`, `ResponseMode` and `Amr` filled in).
  - An `extra` name that repeats a payload member or another extra is refused (`kb_claim_collision`).
  - `sd_hash` = base64url(`sd_alg`(ASCII of `presentation`)).
- `finish_kb(signing_input: &[u8], signature: &[u8]) -> String`.
- `aud`: `VerifiedRequest.client` as `prefix:value` for redirects and signed DC API requests, and `origin:<origin>` for unsigned DC API requests.

**Tests:**
- `nested_parent_included` (Review Focus 1): RFC 9901 Appendix A.2's `address.country` selects the `address` disclosure and the `country` disclosure.
- `empty_paths_disclose_nothing`.
- `sd_hash_known_answer`: the RFC's example presentation and its stated `sd_hash`.
- `aud_for_unsigned_dc_api` (Review Focus 2).

### Task 2.3: mdoc DeviceResponse

**Files:** `crates/siros-mdoc/src/response.rs`.

**Interfaces:**
- `device_response(documents: &[DocumentAnswer]) -> Vec<u8>`, where `DocumentAnswer { document: &Document, elements: &[(String, String)], device_elements: &[(String, String, siros_codec::cbor::Value)], device_signature: &[u8] }`. `device_elements` are the member's `DeviceSigned` transaction bindings (Task 1.7), empty otherwise.
- Encodes `{"version":"1.0","documents":[…],"status":0}`. Each document carries:
  - `issuerSigned.nameSpaces` filtered to `elements` (`encoded` bytes verbatim);
  - `issuerAuth` verbatim;
  - `deviceSigned { nameSpaces: #6.24(bstr .cbor DeviceNameSpaces of device_elements), deviceAuth: { deviceSignature: COSE_Sign1 with protected {1: -7} and a nil payload } }`.
- The signing input is `siros_mdoc::device_message(session_transcript, doc_type, device_name_spaces_bytes)`. The Task 0.4 function gains its third parameter; nym-auth passes the empty map.
- `key_authorizes(mso: &Mso, namespace: &str, element: &str) -> bool` reads `deviceKeyInfo.keyAuthorizations` (ISO/IEC 18013-5 §9.1.2.4).
- The session transcript is `Handover::redirect(client_id, nonce, thumbprint, response_uri)` or `Handover::dc_api(origin, nonce, thumbprint)`, where `thumbprint` is the JWK thumbprint of `ResponseTarget.encryption` or `None`.

**Tests:**
- `round_trip_annex_d_selection`: selecting `family_name` and `birth_date` from Annex D's document decodes back to exactly those two items with their original `encoded` bytes.
- `dc_api_handover_uses_origin` (Review Focus 2): the transcript's handover name is `OpenID4VPDCAPIHandover`, and the digest equals SHA-256(cbor([origin, nonce, null])).

### Task 2.4: `zkp_req` presentation

**Files:** `crates/siros-presentation/src/zkp.rs` wires nym-auth `presenter::{prepare, Prepared::job, Prepared::assemble}` into `prepare`/`finish`.

**Interfaces:**
- `Provers` trait, in `siros-presentation`: `fn prove(&self, job: ProofJob) -> Result<ProofOutput, ProverFailure>`, with nym-auth's types.
- The seed is read from `Credential.auxiliary`: entry `type: "hash_commitment"` at path `["eu.europa.ec.eudi.nym_auth.1","ssc"]`, `opening` base64url of 16 bytes. `opens_ssc` is checked again before `job`.

**Tests:**
- `flow_through_phases`: nym-auth `tests/flow.rs` honest path through `plan`→`prepare`→`finish` with the test prover; the verifier accepts it.
- `tampered_seed_refused_before_prove`: a counting test prover records 0 calls.

### Task 2.5: `vp_token`, encryption, submission

**Files:** `crates/siros-oid4vp/src/{response.rs,jwe.rs}` (feature `crypto`, `aes-gcm`, `p256` `ecdh`).

**Interfaces:**
- `vp_token(answers: &[(String, Vec<String>)]) -> serde_json::Value`: an object keyed by query id with array values (OpenID4VP §8.1). `zkp_req` entries come from `siros_zkp_req::vp_token_json`.
- `encrypt(payload: &serde_json::Value, key: &EncryptionKey, rng) -> Result<String, JweError>`: compact JWE with `alg` `ECDH-ES` and `enc` from `EncryptionKey.enc`, with `kid` when the key has one. The key derivation is Concat KDF per RFC 7518 §4.6.
- `submission(request: &VerifiedRequest, vp_token: serde_json::Value, rng) -> Result<Submission, JweError>`.
- `enum Submission { Post { uri: String, form: Vec<(String, String)> }, DcApi { protocol: String, data: serde_json::Value } }`. The forms are:

| Mode | Shape |
|---|---|
| `direct_post` | form `vp_token`, `state` |
| `direct_post.jwt` | form `response` |
| `dc_api` | `{vp_token}` |
| `dc_api.jwt` | `{response}` |

- `error_submission(request: &VerifiedRequest, code: ErrorCode) -> Option<Submission>`. A user who declines gets `access_denied`.
- `submission_result(status: u16, body: &[u8]) -> Result<Option<String>, SubmitError>`: the verifier's `redirect_uri` from a 200 JSON body (OpenID4VP §8.2), `None` for a body without one, and an error for any other status.

**Tests:**
- `rfc7518_appendix_c_kdf`: the Concat KDF output equals RFC 7518 Appendix C's derived key.
- `decline_sends_access_denied`: the form or data carries `error=access_denied` and the request's `state`.
- `jwe_decrypts_independently`: the test decrypts with its own ECDH and AES-GCM code, written from RFC 7516/7518 only.
- `mixed_request_one_vp_token` (Review Focus 5): a request with an `mso_mdoc` query and a `zkp_req` query gives one `vp_token` with both ids.
- `mode_shapes` (the table above).

### Task 2.6: Presentation record

**Files:** `crates/siros-presentation/src/record.rs`.

**Interfaces:**
- `NewPresentation` (Task 1.1). `presentation_id` and `transaction_id` are random `u32` widened to `u64`, as in wallet-frontend.
- `data` is the serialised `vp_token`.
- `used_credential_ids` are the `credential_id`s of the chosen instances.
- `audience` is the `aud` of Task 2.2.

**Tests:** `record_names_used_instances` (Review Focus 3).

**Gate (M2):**
- Both workspaces' tests exit 0.
- Interop with an independent verifier: the e2e harness (Task 3.6) submits SD-JWT and mdoc responses to vc `sunet/main`'s verifier, over redirect and DC API, and `zkp_req` responses to vc's `zkp_req` verifier stack (`origin/docs/nymauth-verifier-operator`). Each verifier accepts its responses.
- PR M2 after the owner's go.

---

## M3 Facades

### Task 3.1: `siros-wallet`

**Files:** `wallet/siros-wallet/src/{lib.rs,provers.rs}`.

**Interfaces:**
- `LoadedProvers { longfellow: Option<LongfellowProver>, vega: Option<VegaNymAuth> }`.
- `LoadedProvers::load_longfellow(circuits_zst: &[u8])` and `load_vega(shapes_zst: &[u8])` go through the existing pinned `load`.
- `impl Provers for LoadedProvers`.
- `available(&self) -> Vec<AvailableSystem>`.
- It re-exports the phase API of D2 and nothing else.

**Tests:** `unpinned_bytes_refused` is the existing `artifact_pins.rs`, moved.

### Task 3.2: `siros-wallet-uniffi`

**Files:** `wallet/siros-wallet-uniffi/src/{lib.rs,intake.rs,plan.rs,respond.rs,registration.rs}`; `bindings/{kotlin,swift}` regenerated.

**Interfaces:**
- UniFFI records mirroring D2 and Tasks 1.6–2.6. Their JSON wire form is the one the engine uses, so a record serialises identically on every binding.
- Functions: `intake_start_redirect`, `intake_start_dc_api`, `intake_resume`, `plan`, `prepare`, `finish`, `registration_projection` (Task 3.3).
- An exported `Wallet` object holds `LoadedProvers`, built once through `Wallet::new(circuits: Vec<CircuitBytes>)`, where `CircuitBytes { system: String, bytes: Vec<u8> }` names a system id of `NymAuthSystem`.
- Delete: `SirosBlobBuilder`, `match_dc_api_request`, `match_dcql`, `match_dcql_with_context`, `zkp_req_plan` and the branch's `zkp_req_*`.

**Gate:**
- `make bindings && make check-bindings`.
- The Task 3.6 runner through Kotlin and Swift.

### Task 3.3: Picker registration v2 and the picker on the planner

**Files:**
- `crates/siros-picker-registration/src/projection.rs`: `VERSION = 2`, and `golden/` v2 vectors from a fixture wallet.
- `crates/siros-picker/src/main.rs`: it uses `siros-presentation` `picker` with `RequestView::Unverified`, emits through `android-credman`, and takes rows and cards from the projection.

**Interfaces:**
- `registration_projection(credentials: &[Credential], display: &DisplayCache, locales: &[Locale], systems: &[AvailableSystem]) -> Vec<u8>`.
- The projection holds per credential: entry ref, format, type, the typed claim tree minus `NYM_AUTH_UNDISCLOSABLE`, no `auxiliary`, the card and the claim labels; and the system ids.

**Tests:**
- `picker_offers_equal_wallet_offers`: for each Task 3.6 plan case run unverified, the testhost transcript lists the same offers, members and paths as `plan` on the same inputs.
- `projection_holds_no_secret`: the bytes contain neither `ssc` element values nor any `auxiliary` content of the fixtures.

**Gate:** `matcher.wasm` ≤ 307,200 B; ABI check passes.

### Task 3.4: `siros-wallet-web`

**Files:** `wallet/siros-wallet-web/src/lib.rs` (wasm-bindgen; replaces the branch's presenter exports).

**Interfaces:** the functions of Task 3.2 with camelCase names, taking and returning the wire JSON, plus `Wallet.loadLongfellow(bytes)` and `Wallet.loadVega(bytes)`.

**Gate:**
- `wasm-pack build --target web --release`; record the raw and gzip sizes.
- The Task 3.6 runner under Node.

### Task 3.5: `siros-wallet-engine`

**Files:** `wallet/siros-wallet-engine/src/lib.rs` (`wasm32-wasip1`, `cdylib`); `bindings/go/engine/` (Go package, wazero pinned to an exact version, plus `engine_test.go`).

**Interfaces:**
- D4 exports. The ops are `intake_start_redirect`, `intake_resume`, `submission_error` and `parse_submission_result`. They need no credentials and no keys.

**Gate:** `go test ./bindings/go/...` runs the intake and submission vectors with `CGO_ENABLED=0`.

### Task 3.6: One vector suite through every binding

**Files:**
- `vectors/{intake,plan,respond}/*.json`: request, state, cache and systems, expected step, offers or submission.
- Respond cases use fixed signatures, fixed `iat` and a seeded RNG.
- Runners: `crates/siros-presentation/tests/vectors.rs`, `bindings/kotlin/src/test/.../VectorsTest.kt`, `bindings/swift/Tests/VectorsTests.swift`, `wallet/siros-wallet-web/tests/vectors.mjs`, `bindings/go/engine/vectors_test.go` (intake cases), and the picker testhost (plan cases, unverified).
- `e2e/tests/interop.rs` (ignored tier) starts vc's verifier and posts the respond cases' submissions.

**Gate:** all six runners give results identical to the Rust runner (diff of their JSON outputs is empty).

**Gate (M3):** PR M3 after the owner's go; release `v1.0.0-rc.1` of the AAR, the XCFramework and the npm package after the owner's go.

---

## M4 Adoption (one PR per repo, each after the owner's go)

Decision O1 must be settled before the deletions in Tasks 4.1–4.3 that serve `mso_mdoc_zk`.

### Task 4.1: siros-sdk-kotlin

**Replace with core calls:** in `sdk/wallet/.../SirosWallet.kt`, the DC API path, the engine `credential_selection`, `match_request` and `sign_request` handling, and the WMP `match()`. They become `intake_*`→`plan`→listener→`prepare`→wscd signing→`finish`. `WalletEventListener` receives `ConsentView` and returns `Selection`.

**Delete:**
- `SC/{CredentialMatcher,SharedDcqlMatcher,CircuitZkMatching,SharedCircuitZkPlanner,RulebookCircuitZkValidator,CircuitZkResponse,ProofTime,NonDisclosure,PresentationConsent,ZkCircuitClient}.kt`.
- `SW/dcapi/{DCAPIRequest,DCAPIRequestRules}.kt` and `SW/transaction/*`.
- `SK/{CircuitZkPresenter,CatalogCircuitZkProver,CircuitZkSystemAdapter,NymAuthCircuitZkAdapter,LegacyZkCircuitZkAdapter,DCAPIResponseEncryption}.kt`.
- The OpenID4VP use of `SK/MdocDeviceResponseBuilder.kt`.
- The disclosure filters in `SK/JweKeystore.kt` and `SK/WscdKeystoreAdapter.kt`.
- `spec/zkp-req-vectors`.

**`SirosCredentialRegistry`:** it registers `registration_projection` with `matcher.wasm`.

**Gate:**
- `grep -rn 'dcql_query\|claimsPath\|filterDisclosures\|DeviceResponse(' sdk/` gives 0 outside generated bindings.
- `./gradlew test` passes.
- The sample app completes DC API and redirect presentations of SD-JWT, mdoc and `zkp_req` against vc's verifier on a device or emulator.

### Task 4.2: siros-sdk-swift

The same replacement in `SirosWallet+DCAPI.swift`, `SirosWallet+Engine.swift` and `SirosWallet+EngineSelection.swift`.

**Delete:**
- `SirosCredentials/{CredentialMatcher,SharedDcqlMatcher,ZkProofSystem,BbsProofSystem}.swift` (BBS is unsupported in the ecosystem).
- `SirosCredentials/ZkpReq/` and `SirosCredentials/CircuitZk/`.
- `SirosWallet/DCAPIRequestParser.swift` and `TransactionData/`.
- `SirosKeystore/{DCAPIResponseEncryption,LongfellowZkProofSystem,VegaProofSystem}.swift`.
- The disclosure filters of `JweKeystore.swift` and `WscdKeystoreAdapter.swift`.

The macOS target links the XCFramework too, so the built-in matcher has no remaining use.

**Gate:** the same grep over `Sources/`; `swift test`; the SampleApp completes the same presentations on a simulator.

### Task 4.3: siros-wallet-frontend

**Replace:**
- `src/lib/services/CredentialMatchingService.ts` (`dcql` dependency removed).
- The selection and consent building of `src/hooks/useOID4VPFlow.ts`.
- The SD-JWT and mdoc builders of `src/hooks/useOIDFlowSignHandler.ts`, `src/lib/verifiable-credentials/formats/{sd-jwt,mdoc}.ts`.
- `src/lib/openid-flow/platforms/dc-api/{DCAPIRequest,DCAPISession}.ts` request reading and encryption.

All of these become `@sirosfoundation/siros-wallet` calls. The WebSocket transport speaks D10.

**Delete:** `packages/wallet-common/src/protocols/openid4vp/OpenID4VPServerAPI.ts` (no caller). The branch `323-abstract-the-wallet-to-accept-any-zero-knowledge-method-longfellow-vega-bbs-etc` closes as superseded once its owner agrees.

**Gate:**
- `grep -rn "from 'dcql'" src packages` gives 0.
- The frontend test suite passes.
- A browser run completes redirect (through the engine) and DC API presentations against vc's verifier.

### Task 4.4: go-wallet-backend

**Engine:**
- The OpenID4VP flow in `internal/engine/oid4vp.go` runs intake through `bindings/go/engine` (vendored, or a module from siros-dc-matcher) and executes `Fetch` and `Trust` with its existing HTTP client and trust evaluator.
- It sends `presentation_request`, receives `presentation_response`, and POSTs the `Submission`.

**Delete:**
- `checkConsentAgainstDCQL`, `vetConsent`, `claimPathMatcher` and `matchJoinedPath` (`internal/engine/oid4vp_consent.go`). The client now builds the response from the plan.
- `buildDCQLVPToken`.
- The `match_request` handlers (`session.go`, `handler.go`) and their spec section.

**Gate:** `CGO_ENABLED=0 go build ./...`; `go test ./...`; the web e2e of Task 4.3.

### Task 4.5: wallet-android-wrapper

- The frontend computes `registration_projection` (web core).
- The wrapper registers `matcher.wasm` with it through `RegistryManager`, in place of `OpenId4VpRegistry`.
- The picker's set and entry metadata (`query_id`, `credential_id`) go to the frontend, which maps them to a `Selection`.

**Delete:** `WJ/json/DcApi.kt`'s stock entry builder.

**Gate:** an emulator run shows the picker entries the frontend's plan lists, and completes the presentation.

### Task 4.6: Documentation

- Rewrite siros-dc-matcher `README.md` (purpose, crates, build) and replace `docs/plan.md` with this plan's D1–D10 as `docs/architecture.md`.
- Update `docs/abi.md` for registration v2.
- `go-wallet-backend/docs/websocket-protocol-spec.md` gets D10 and drops `match_request`.
