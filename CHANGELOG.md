# Changelog

Notable changes to the matcher, its AAR/XCFramework, the wallet core crates, and
the `siros-dcql` crate. The crate keeps [its own changelog](crates/siros-dcql/CHANGELOG.md),
because it is published to crates.io and versioned independently of this
repository.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Entries are reconstructed from git history for releases made before this file
existed.

## Unreleased

Adopts the `zkp_req` draft 0.1 and the nym_auth catalogue 0.5 (nym_auth rulebook repository,
commit `e65861c`), and adds the components of the SIROS wallet core.
**Breaking**: requests and presentations follow the draft, the FFI loses `zkp_req_plan`, and the
vectors move to the crates that own their rules. Consumers that keep a copy of the vectors
(siros-sdk-kotlin, siros-sdk-swift) must re-copy them from the new directories; the vector set
digest below identifies them. `matcher.wasm` is 300,441 bytes
against the 307,200-byte budget (303,418 at v0.11.0).

### Changed

- **BREAKING (request):** a query's options are its `_req_sets`, arrays of `_req` indexes;
  without `_req_sets`, `_req` is the one option (`zkp_req`, Section 2.1). `return` is optional
  except on `pseudonym`. `vp_formats_supported.zkp_req` requires both `proof_backend_values`
  and `system_id_values` (Section 1.2), so a `zkp_req` query matches only with the request's
  `client_metadata`; `proof_system_values` is gone. `age_check` takes `range` (`A-B`, `A+`,
  `B-`), and the Wallet derives E and C at the proof date; `ge`, `le` and the 365-day rule are
  gone.
- **BREAKING (matcher):** a registered circuit is a system of Section 1.3: its `system_id`
  param is the system and its `system` the proof backend, matched against
  `proof_backend_values`. The matcher answers the first option a circuit serves, and the picker
  rows name that option's functions. `FfiMatchedCredential.zkp_req` is
  `{circuit, proof_backend, req_set?, items}`.
- **BREAKING (presentation):** `ZkpPresentation {system_id, proof_backend, ? req_set, proof,
  results}` (Section 4), where `proof` is the CBOR `Proof {inputs: {issuer_key_set,
  proof_time}, zk_proof}` of the proof backends. The CBOR reader allows nesting depth 32
  (16 before).
- **BREAKING (FFI):** `zkp_req_plan` and `ZkpReqPlanError` are removed. Bindings are
  regenerated.
- The matcher calls the host through the new `android-credman-sys` and
  `android-credman` crates (MIT OR Apache-2.0, from
  APTITUDE-Consortium/dcapi-matcher). `crates/android-credman-sys/ABI.md`
  documents the host ABI.
- Below host level 2 the matcher emits nothing; it used to call the
  `credman_v2` functions regardless.
- On level 2 and above, the matcher emits nothing when the host's inputs are
  malformed: a calling-app origin without a terminating NUL or with invalid
  UTF-8, or a read that reports more bytes than it wrote. It used to emit
  entries from such inputs. A debug build emits one entry that names the
  fault.
- The registered blob is read until complete; a short
  `ReadCredentialsBuffer` read used to leave its tail zeroed.
- `siros-dc-matcher-core`'s unused `sink` module is removed.
- Entry metadata is the standard object
  `{"display_skipped":bool,"host_level":n,"data":{…}}`. The matcher's own
  members moved under `data`; `host_abi` became `host_level`.
- A NUL inside a picker string becomes a space; it used to end the string.
- **BREAKING (Rust API):** `siros-dc-matcher-core`'s `request` module is `siros-oid4vp`'s
  `UnverifiedRequest` and `UnverifiedQuery`. An entry reads only under the three protocols of
  OpenID4VP 1.0, A.1; a profile label outside them reads as no protocol.
  `UnverifiedRequest::first_registered` and `diagnose` take the registration as a label
  predicate, and `ProfilePolicy::with_context` takes the query and `client_metadata`.
  `first_supported_request` and the entry predicate are removed. The public modules `base64url`
  and `purpose` are removed: siros-codec's `base64url` and siros-display's `purpose` hold them.
- **BREAKING (Rust API):** `siros-dcql` 0.12.0: the Credential Query `id` is a `QueryId` (§6.1),
  which the query parse refuses outside its characters, and `resolve` runs §7.1.1 over any claim
  tree that implements `ClaimNode`. See [its changelog](crates/siros-dcql/CHANGELOG.md).

### Fixed

- `matcher.wasm` v0.8.0 to v0.11.0 imported `wasi_snapshot_preview1.random_get`,
  which the host lacks, and trapped on `zkp_req` requests. `siros-dcql`'s
  `DcqlQuery::validate` uses `rustc-hash`'s `FxHashSet`, which takes no seed, and the `zkp_req`
  crates use no seeded collection. `siros-dcql` depends on `rustc-hash`.

### Added

- `siros-codec`, the encodings every wallet core crate shares: a strict CBOR reader (definite
  lengths, no duplicate keys, no trailing bytes, at most `cbor::MAX_DEPTH` (32) levels) and a
  deterministic writer; unpadded base64url and the padded base64 of `x5c` certificates (RFC
  4648, Sections 4 and 5); and the calendar dates and UTC times of CBOR's `full-date` and
  `tdate`. Every function returns a value or an error on every input.
- `siros-sdjwt`, SD-JWT VC (RFC 9901): `SdJwt::parse` reads a stored credential with the checks of
  Section 7.1 (S1), `SdJwt::claims` walks its claim tree with the issued array positions (S2), and
  `SdJwt::root` gives the `Node` that `siros_dcql::resolve` walks (Q4). `SdJwt::select` gives
  the `Presentation` of the claims a set of claims path pointers selects, with each disclosure on
  the path and inside the value once (S3). `Presentation::key_binding` gives the KB-JWT signing
  input, with `sd_hash` over the presentation as sent and the extra claims, and refuses a claim
  name that collides (`KeyBindingError`, S4); `KeyBinding::assemble` turns the host's ES256
  signature into the SD-JWT+KB. Types that hold claim values or salts implement no `Debug`.
- `siros-mdoc`, ISO/IEC 18013-5 mdocs: `Mdoc::parse` reads a stored credential (the base64url of
  an `IssuerSigned`, a `Document`, or a `DeviceResponse` with one document) with its MSO, keeps
  the bytes the issuer wrote, and refuses a `docType` other than the MSO's and an item without the
  digest `valueDigests` lists. `Mdoc::disclose` selects items and the `DeviceSigned` elements the
  response carries, and refuses an element the MSO's `KeyAuthorizations` leave unauthorized
  (`DisclosureError`, M3). The `Disclosure` gives the data the device key signs and, with that
  signature, the `DeviceResponse`, which carries the items in their issued bytes and `issuerAuth`
  verbatim (M2). `device_signing_input` gives the same data from a session transcript, a
  document type and the `DeviceSigned` namespaces alone. With
  the feature `crypto`: the Document Signer certificate (`P256Certificate`), ES256 verification
  (`es256_verifies`) and `P256Key::new`.
- `siros-oid4vp`, OpenID4VP 1.0 for the wallet core. Without `crypto` it holds the picker's
  request reading (`UnverifiedRequest`, `UnverifiedQuery`, `diagnose`), `ClientId`, whose parse
  refuses with a `ClientIdError`, an `x509_san_dns` value that is not ASCII included, and the
  mdoc `Handover` with `ec_jwk_thumbprint`: `Handover::dc_api` and `Handover::redirect` take the
  encryption key thumbprint as an `Option`, `None` being CBOR `null` for an unencrypted response
  (B.2.6). It builds with Rust 1.82. With `crypto`: sans-IO intake of redirect requests (by
  value, `request`, `request_uri` with `get` or `post`) and DC API requests (unsigned, signed,
  multisigned) into a `VerifiedRequest`, with `Fetch` (`Fetch::get`, `FetchResponse::status`,
  `FetchResponse::body`) and `Trust` effects for the host; the Client Identifier Prefixes
  `x509_san_dns`, `x509_hash`, `decentralized_identifier`, `verifier_attestation`,
  `openid_federation` and `redirect_uri`; ES256 Request Objects; the `vp_token`
  (`VpToken::json`), its submission per Response Mode, `ECDH-ES` response encryption with
  `A128GCM` or `A256GCM`, error submissions, and the reply to a direct post. `direct_post.cwt`
  (`zkp_req.md`, Section 6.2) posts the CBOR Authorization Response in a `COSE_Encrypt` by
  ECDH-ES + HKDF-256 with `A128GCM`, `A192GCM` or `A256GCM`.
  `VerifiedRequest::access_certificate` gives the `CertificateDer` and the `SemanticIdentifier`,
  or the `SemanticIdError`, of an `x509_san_dns` or `x509_hash` signer's certificate: the WRPAC
  policy (ETSI TS 119 411-8) says whether its subject is a natural person, identified by its
  `serialNumber`, or a legal person, identified by its `organizationIdentifier` (ETSI TS 119
  475, Clauses 5.1.3 and 5.1.5). `dc_api_protocol` gives the DC API protocol, and
  `verifier_info_formats` the `AttestationFormat` of each `verifier_info` attestation (Section
  5.1). Intake refuses a malformed `verifier_info` with the `VerifierInfoRule` it breaks.
- `siros-zkp-req`, the `zkp_req` protocol layer: the Credential Query with `_req` and `_req_sets`,
  `vp_formats_supported.zkp_req`, the usable pair of Section 1.3, the consent model,
  `ZkpPresentation` with the backends' `Proof`, the `vp_token`, and the Verifier's steps 1 to 5
  of Section 4.1. It holds Rust 1.82.
- `siros-zkp-req-nym-auth`, the nym_auth catalogue with the Longfellow and Vega systems, the
  session binding, the Wallet's credential tests, a presenter in phases and the Verifier's
  checks, behind `NymAuthProver` and `NymAuthProofVerifier`. It holds Rust 1.82.
  - Each test of a query or a credential is the constructor of its result.
    `NymAuthQuery::from_query` gives `Catalogued`: `NymAuth`, or `OtherType` for another
    credential type. `UsableAttestation::new` tests a stored credential and
    `UsableAttestation::of` an mdoc already parsed; their refusal `Unusable` carries the Section 9
    codes. `OpenedSeed::open` opens the `ssc` with the `SecretSeed`. `NymAuthQuery::options`
    gives each option's `UsablePair` with its `ProofBackend`, and an `Answer` holds a pair, a
    usable attestation and the opened seed. `prepare` builds through them, `Prepared::new` gives
    the `Prepared` of an answer in a `NymAuthRequest`'s session, and only `Prepared::job` builds a
    `ProofJob`.
  - `NymAuthRequest` (feature `request`), the nym_auth request of a verified request, with the
    session of its `Handover`. The request is signed by a Request Object or under
    `openid4vp-v1-signed`, trusted, encrypted, and carries no registration certificate
    (`unsigned`, `multisigned`, `untrusted`, `response_mode`, `registration_certificate`). Its
    `verifier_id` takes the `VerifierIdForm` of the trust framework: `semantic_id:` and the
    access certificate's semantics identifier (`VerifierId::semantic` takes a
    `SemanticIdentifier`), or `x509_san_dns:` and the Client Identifier
    (`VerifierId::x509_san_dns` takes a `ClientId` and an `Intermediary`); a certificate without
    one is refused with its `VerifierIdRule::SemanticId` reason.
  - `NymAuthSystem::circuit_artifact` gives the circuit artifact pins of the system rulebooks'
    Section 8.
- `siros-wallet-state`, the decrypted wallet state `S` of the private data container
  (privatedata 3.1, Section 6): `WalletState::parse` reads `schemaVersion` 3 or 4, absent meaning
  1 (W1), into its credential entries with unique 64-bit `credentialId`s and their `metadata`
  verbatim (W2), its presentation records and its key identifiers (W3). `PresentationRecord::new`
  gives the record the host appends as a `new_presentation` event (W4).
  `CredentialId::new` is public, for the ids picker entries carry, and `InstanceId` displays its
  decimal form. Types that hold a credential, a presentation or a `metadata` value implement no
  `Debug`.
- `siros-credential`, the format-independent credential: `Credential::parse` reads a wallet
  state entry through the format crates (C1) into claims that keep their type (C2), with claims
  path pointers (`ClaimPointer`, C3, which also gives the components SD-JWT selection takes), validity at a time (`UsableCredential::at`, C4) and the
  holder's P-256 key (`Credential::holder_key`: an SD-JWT VC's `cnf.jwk` or an mdoc's
  `deviceKey`; an SD-JWT VC whose `cnf` holds no P-256 `jwk` does not parse,
  `CredentialError::HolderKey`). `least_used` chooses the instance of a batch among any
  `Instance` (C5).
- `siros-display`, display for the wallet core: display metadata (`IssuerMetadata`,
  `TypeMetadata`, `DisplayCache`) and its locale choice (`Locale`, `choose`, `preferred`: the
  exact tag, then the primary language, then the first entry), credential cards and claim rows,
  where SD-JWT VC Type Metadata display wins over `credential_metadata`, values typed for
  display (`DisplayValue`), `DisplayText`, purpose lines (`purpose`), and the proof statement
  rows of a `zkp_req` option: the picker's, marked as unverified (`proof::rows`), and a verified
  request's, each a `DisplayText` label and value held whole (`proof::verified_rows`).
- `siros-transaction-data`, the `transaction_data` request parameter (OpenID4VP 1.0, Section
  5.1) for the wallet core. It parses entries of the four EC TS12 v1.0.1 types into typed
  payloads, binds each entry to one credential of an offer, gives the KB-JWT claims
  (`transaction_data_hashes`, `transaction_data_hashes_alg`, `jti`, `response_mode`, `amr`)
  and the consent display, and asks the host to fetch the SD-JWT VC type metadata and the
  documents it references. It builds with Rust 1.82. `Entry::carried_by` and `Entry::names` give
  the one rule of an entry naming a Credential Query, with `Entry::credential_ids` and
  `Presented::query_id` as `QueryId`s; `Fetched::insert_first` records the first response to a
  URL, and `Fetched::response` reads it.
- `siros-presentation`, the presentation component of the wallet core. Phase 1 plans a
  verified request over the wallet's credentials usable at the plan's time: the format table,
  `meta`, holder binding and no query but `zkp_req` on a nym_auth attestation (A1); `zkp_req` as
  one selection, then the usable attestation and the seed delivered in the credential's
  auxiliary data (A2); offers, optional additions, an offer per option when every set is
  optional, a `multiple` member holding every candidate, and, for an offer whose members leave a
  transaction entry uncarried, each option of an optional set that can carry it joined in an
  offer of its own, repeated until every entry is carried, at most one option per set (A3).
  An offer that cannot carry every entry is dropped, two offers with the same members are one,
  and the joins spend the examination budget and count among the combinations not examined.
  `Offers::of` gives the first `Refusal`: an offer no join completes, or one the acceptance
  refuses. The plan also gives the transaction entries each credential authorizes, the credential named by
  `credentialId` and instance (T4); the plan's digest over the request, its trust verdict, the
  nym_auth `verifier_id` and every offer's credentials by `credentialId` and instance, their
  answers and bound entries, its additions and display (A4); and the consent
  view with cards, claim rows, proof statement rows, additions, transactions and whether an
  offer needs the wallet's display (A9). The plan asks the host for each type metadata fetch.
  A nym_auth request must be signed, trusted and encrypted, and its `verifier_id` comes from the
  authenticated certificate (N2). A `zkp_req` query that names `trusted_authorities` finds every
  issuer untrusted until the wallet evaluates them. Phase 2 parses the selection against the
  plan made again, with the non-empty subset of each `multiple` member by `credentialId`, kept
  in the member's order. A selection that leaves out the credential an entry binds to is
  refused, and phase 2 binds the entries to the credentials the view named. `Planned::picked`
  makes the selection from the credential picker entries the user picked, each naming its
  offer, query and `credentialId` (K3). Phase 2 gives a `Sign` effect per signing input,
  verifies each signature under the instance's holder key (A5), and gives
  one `vp_token` (A8), its submission for the request's Response Mode and the presentation
  record. It proves `zkp_req` in-process through a `NymAuthProver`. A decline, and a background
  fulfilment of an offer that needs the wallet's display, give `access_denied`. Positions and
  identifiers are their own types (`QueryIndex`, `CandidateIndex`, `SetIndex`, `OfferIndex`,
  `AdditionIndex`, `EntryPosition`, `PlanDigest`, `SignId`, and DCQL's `QueryId`),
  and so are A9's facts. `Fetches` is the one store of the host's responses, and a second
  answer to a URL is refused. A request without an offer gives its `Failure`: the refused query and why,
  the reasons each `zkp_req` candidate answers no option, or no combination. Without the
  default feature `wallet` it holds the matching for the picker, over `MatchCredential`, and
  builds with Rust 1.82.
- The `proving/` workspace: `siros-zkp-backend-longfellow` and `siros-zkp-backend-vega`
  implement the prover and verifier of each system over zk-cred-longfellow and zk-cred-vega,
  and check the circuit artifact the host fetched against its pin. CI runs real proofs of both
  systems. The matcher compiles no prover.
- FFI module `zkp_req`: `zkp_req_match`, `zkp_req_session`, `zkp_req_jwk_thumbprint`,
  `zkp_req_prepare` with `FfiPrepared`, `zkp_req_vp_token_json`, `zkp_req_vp_token_cbor`, and
  `zkp_req_verify` with a host-implemented `FfiProofVerifier`, whose `FfiProofCheck::Internal`
  reports a verifier that failed on its own inputs.
- `siros-zkp-req-wasm` (in `proving/`), the presenter for the browser with both provers on one
  thread: `ZkpProvers` loads the artifacts, `ZkpPrepared.prove` returns the presentation. CI
  lints and builds it for `wasm32-unknown-unknown` and checks its imports.
- Vectors: 50 protocol request vectors (`crates/siros-zkp-req/tests/vectors/request`), 72
  catalogue request vectors and 149 presentation vectors
  (`crates/siros-zkp-req-nym-auth/tests/vectors/`, the latter from
  `scripts/gen_zkp_req_presentation_vectors.py`), the `proof_time` vectors, the session and
  pseudonym vectors of zk-cred-vega, and `readdit.json`, the values of readdit `1cf3f26` for a
  differential test. Each changed expectation carries a `v0_4` note.
- Docs: `docs/zkp_req_core.md` (crates, flow, prover interface, API); `docs/zkp_req_request.md`
  and `docs/zkp_req_response.md` follow the draft; `docs/ecosystem.svg`, the README's overview
  of the layers, written by `scripts/gen_ecosystem_svg.py`.
- Vector set digest (`scripts/vectors_digest.sh --digest`):
  `4f0051624517ffb427af9c93de2d119f179304c6e218776f9a8e2b93a41b2a06`. The capability vectors
  (`circuit_capabilities/match.json`) are unchanged.
- `scripts/check_matcher_abi.py` checks each import of `matcher.wasm`, with
  its signature, against the ABI table, and the `_start` and `memory`
  exports. CI and the release job run it.
- `clippy.toml` forbids std's `HashMap`, `HashSet` and `RandomState` in the
  crates that link into `matcher.wasm`.

### Removed

- From `siros-dc-matcher-core`: the v0.4 planner (`zkp_req`), the response validator
  (`zkp_req_response`), `proof_time`, their vectors (`zkp_req`, `zkp_req_response`,
  `zkp_req_unsat`, `proof_time`) and `scripts/gen_zkp_req_response_vectors.py`.
- `docs/plan.md`, the plan of the first release.

## v0.11.0 — 2026-10-20

Adopts the `nym_auth` rulebook v0.4. **Breaking** (a minor bump, pre-1.0): the
FFI was renamed, so a consumer must regenerate its bindings, and **wallets must
re-register**: a credential blob built before this release has no `zkp_req`
format rule and declines the format. `siros-dcql` and `siros-dc-matcher-core`
are versioned 0.11.0 to match the release; `siros-dcql` has no change.
Consumers that keep a copy of the vectors (siros-sdk-kotlin, siros-sdk-swift)
must re-copy `zkp_req`, `zkp_req_response`, `zkp_req_unsat` and `proof_time`
from the v0.11.0 tag; the vector set digest below identifies them.
`matcher.wasm` is 303,418 bytes against the 307,200-byte budget.

### Changed

- **BREAKING (rulebook v0.4):** the matcher follows
  `nym_auth_rulebook` v0.4 (`fea9a0a`). Names: `circuit_zk` is `zkp_req`
  (format, capability family, modules, FFI `add_zkp_req_system`,
  `zkp_req_plan`, `ZkpReqPlanError`, `FfiMatchedCredential.zkp_req`), `req` is
  `_req`, request item `id` is `fn_id`, `pseudonym-v1-sha256` is `pseudonym`,
  `circuit_id` is `system_id` (registration param `system_id`),
  `circuit_id_values` / `circuit_proof_system_values` are `system_id_values` /
  `proof_system_values`, the plan's `circuit_filter` is `system_filter`
  (`system_ids`). The request carries `meta.source_format` (`mso_mdoc`,
  `bbs_cd`); `pseudonym` takes `config`, `ver` (integer) and `prf`;
  `verifier_id_type` is gone (an undeclared parameter if sent). The rulebook
  example shape (`claims._req`, `{fn_id, input}` envelope) is not a request
  shape any more. Bindings are regenerated. Wallets must re-register: a blob
  built before this change has no `zkp_req` format rule and declines the
  format. Capability catalogs that name the presentation `circuit_zk` must say
  `zkp_req`, and a `pseudonym` entry must list `config`, `ver` and `prf`.
- **BREAKING (response):** a presentation is the base64url (unpadded) CBOR
  `ZkpPresentation {system_id, proof, issuer_key_set, ? proof_time, results}`
  (rulebook v0.4), replacing the JSON shape. `issuer_key_set` replaces
  `x5chain` (DER certificates as byte strings; limits kept: 8 elements, 4096
  bytes each); `proof_system` and `circuit_id` are not members; a pseudonym is
  a byte string (32 for `prf` `sha-256`, 48 for `hashdh-bls12381g1`), a
  predicate result is `true`. Strict CBOR: definite lengths only, no duplicate
  keys, no trailing bytes. `proof_time` (tag-0 tdate) must be the exact 20-byte
  form and is required for `mso_mdoc`. All response vectors are regenerated
  (143, by `scripts/gen_zkp_req_response_vectors.py`); refusal codes are new
  (see the vectors README).
- The evaluator never offers a request the rulebook calls unsatisfiable
  (`zkp_req::unsatisfiable`, 16 codes, vectors in `tests/vectors/zkp_req_unsat`),
  and requires the stored attestation to be of the request's `source_format`.
  Which configurations a circuit supports remains its capabilities' say.
- Non-disclosure: a request through any format other than `zkp_req` for `ssc`,
  `psc`, `secret_seed` or `birth_date` of a nym_auth attestation (including a
  wildcard path, or no `claims`) does not match it. `birth_date` of other
  credentials is unaffected.

### Added

- `proof_time` module: `render` / `parse` of the exact 20-byte
  `YYYY-MM-DDThh:mm:ssZ` form and `check_tolerance` (recommended 60 s skew,
  600 s age, configurable); vectors in `tests/vectors/proof_time`.
- Docs `docs/zkp_req_request.md`, `docs/zkp_req_response.md` (renamed from
  `circuit_zk_response.md`), and `scripts/vectors_digest.sh`.
- Vector set digest (sha256 of the sorted `sha256sum` manifest of
  `zkp_req`, `zkp_req_response`, `zkp_req_unsat` and `proof_time`):
  `9f482d7a3fb87cb1381d0dfb7a2fc396b6cd3c1eba07c5d76f44e47142b751ac`.
  The capability vectors (`circuit_capabilities/match.json`) are unchanged:
  `ab2e4f07ca6399e56cef486831ce1447fb772e13f3420af3a8d36d732153e8e9`.

The unreleased JSON response shape of #48 and #49 (with `x5chain`) is
superseded by the CBOR shape above and was never released.

## v0.10.0 — 2026-10-15

Behaviour change (a minor bump, pre-1.0): the capabilities parser now follows
the circuit catalog's rename of `credential.profile` to
`credential.issuance_profile` (go-zk-circuits #36). No FFI or plan-JSON change,
nothing to regenerate. `siros-dcql` and `siros-dc-matcher-core` are versioned
0.10.0 to match the release; `siros-dcql` has no change.

### Changed

- `credential.issuance_profile` is accepted: an optional, non-empty opaque
  string that constrains the input credential (it is not an interop profile).
  It is validated (empty, null or non-string fails closed) and otherwise
  ignored: it never filters, ranking being the wallet's job.
- The old key `credential.profile` is now an unknown member like any other, so
  the capabilities fail closed and the circuit is not offered. Nobody should
  have been using it: no published catalog carried `profile`.
- Capability vectors (`tests/vectors/circuit_capabilities/match.json`, sha256
  `ab2e4f07ca6399e56cef486831ce1447fb772e13f3420af3a8d36d732153e8e9`): the
  `profile-preferred`, `profile-conformant` and `profile-before-status` cases
  use `issuance_profile` (expectations unchanged; membership only); new cases
  `issuance-profile-served`, `legacy-profile-key-fails-closed` and
  `issuance-profile-empty-fails-closed`. The two fail-closed cases carry
  `expectRejected`: the capabilities themselves must not parse.

Consumers that keep a copy of the vectors (siros-sdk-kotlin
`spec/circuit-capabilities-vectors`, siros-sdk-swift) must re-copy them from the
v0.10.0 tag and update their recorded provenance. The Kotlin pinned AAR should
move to 0.10.0 once it is on Maven Central.

## v0.9.1 — 2026-10-15

Tests, vectors and docs only: no behaviour change, no FFI or plan-JSON change,
nothing to regenerate. The `circuit_zk` planner vectors changed (see below), so
a consumer that keeps a copy of them (siros-sdk-kotlin
`spec/circuit-zk-planner-vectors`, siros-sdk-swift) should re-copy them from the
v0.9.1 tag rather than from commit 9237638, and update its recorded provenance.
`siros-dcql` and `siros-dc-matcher-core` are versioned 0.9.1 to match the
release; neither has a change.

### Changed

- `circuit_zk` planner vectors and tests follow the `nym_auth` rulebook change
  that removes `verifier_id_type` from the request (how a verifier is identified
  is now agreed in the shared trust framework: `semantic` or an OpenID4VP
  client_id_type name). The planner still accepts the param and passes it
  through as an opaque optional string, and the plan's `verifier_id_type` stays
  an `Option`, `None` when absent; no function requires it. Vectors
  `ok_normative_plain`, `ok_example_envelope`, `ok_opaque_strings`,
  `err_duplicate_handle` and `err_example_duplicate_handle` no longer carry it;
  new `ok_legacy_verifier_id_type_accepted` is the one vector that does. New
  sha256:
  - `err_duplicate_handle.json`: `0a94dbb8a02535d4ce657b6cdc747bf58de160d91a2a50a80e645c16da8801ed`
  - `err_example_duplicate_handle.json`: `0811cad0d2d7ff7b22697537cb55aafecb4de3415199a512227b1e2142629cd9`
  - `ok_example_envelope.json`: `6df46456fc8db63dc1da1c1707916122be8ed153d78f539cf3d14e9f6613e83f`
  - `ok_normative_plain.json`: `1cd414d36529eb92d530ff6754779ed8ca600ce459ffdb33a4ee3acd8ac848e5`
  - `ok_opaque_strings.json`: `c039c8fd0c129d0f6283b1e08d5775e1c490726b2e39e2162ca5b402ad8c9e3e`
  - `ok_legacy_verifier_id_type_accepted.json`: `0cd2976e365f69ca9830434e2b89a1fb064f1b1a2a7a82e1410c59103e7b643c`
  - `circuit_capabilities/match.json` is unchanged
    (`9bee1868fd957fd4ad56a91dbca93b922ede04bfa57bb0f8b3a3c9bd5f383866`); it never
    carried `verifier_id_type`.
- Capability tests no longer send or declare `verifier_id_type`; the enum and
  unlisted-param constraints are exercised with `config`. New test
  `a_legacy_verifier_id_type_param_is_not_served` shows a request carrying the
  param is not served by a circuit that does not list it.

## v0.9.0 — 2026-10-14

Lets a wallet read the `circuit_zk` plan directly, and describe what a registered
circuit can do. The FFI gained a function and an error type, so a consumer must
regenerate its bindings. Registrations that use neither new param behave as in
0.8.0. `siros-dcql` and `siros-dc-matcher-core` are versioned 0.9.0 to match the
release; neither has an API change in this release.

### Added

- FFI `circuit_zk_plan(credential_query_json, client_metadata_json)`: returns
  the normalised plan as JSON, or `CircuitZkPlanError.InvalidRequest { code,
  reason }` with the planner's own stable code. It is a thin wrapper over
  `circuit_zk::plan`, the function matching already calls, so a wallet no longer
  needs a probe blob to read a plan. The plan JSON (`functions`,
  `circuit_filter`, `meta_doctype`, `raw`) is documented on the function and is
  the same object as the `plan` member of a match. Tested against every planner
  vector.
- `add_circuit_zk_system` accepts two more opaque params, both optional.
  `credential_type` restricts a circuit to one credential type: it is offered
  only for a request whose `meta.doctype_value` equals it or whose
  `meta.vct_values` contains it (a request naming neither is not offered a
  restricted circuit). `capabilities` carries the circuit catalog's
  `capabilities` object as a JSON string; when present it replaces `functions`
  and `credential_type`, and the matcher applies its capability rule: presentation and credential type equal
  the request's, every requested function is declared with params its
  constraints accept and within `max`, and every `always` function was
  requested. A `capabilities` value that does not parse (unknown keys,
  schema other than 1, malformed) never errors at registration; the circuit is
  not offered. A registration without these params behaves as in 0.8.0.
  The rule is held to a vector corpus that this repository owns and the SDKs
  copy (`tests/vectors/circuit_capabilities/`).
- The registered blob format is unchanged: the new params are ordinary
  capability params, the profile content is the same, so the golden blob and
  `db::VERSION` are unchanged.

## v0.8.0 — 2026-10-14

Adds the `circuit_zk` (nym_auth) format: planner, request context and matching.
The FFI records gained fields, so a consumer must regenerate its bindings.

### Added

- `circuit_zk` query planner in `siros-dc-matcher-core` (`circuit_zk::plan`):
  parses and normalises a `circuit_zk` credential query in both rulebook
  shapes (`req` and `claims._req`), and rejects structural defects only.
  Not yet wired into matching. Conformance vectors in
  `crates/siros-dc-matcher-core/tests/vectors/circuit_zk/` are reusable by the
  SDKs. (#37)
- `request::first_supported_context` (and `_in`, `extract_context`): returns the
  full `RequestContext` (protocol, signed flag, `client_id`, `expected_origins`,
  `client_metadata`, raw and parsed `dcql_query`) and takes an optional caller
  predicate, so the first entry the caller accepts wins. `first_supported_request`
  is now a thin wrapper with an unchanged signature. A `circuit_zk` request with
  `claims` as an object yields a context (`dcql_query: None`) instead of
  `NoQuery::Malformed`. Signatures and origins are still not checked. (#38)
- `circuit_zk` matching: `siros_default()` maps `circuit_zk` onto stored
  `mso_mdoc` (doctype through the existing meta rule), and the evaluator answers
  it from the planner's output. A structurally invalid request matches nothing
  and never falls back to claim matching; the matcher applies no
  satisfiability rules. Wallets register circuits with a new `circuit_zk`
  capability family (`SirosBlobBuilder::add_circuit_zk_system`: proof system in
  `system`, opaque string params; `circuit_id`, and optionally `functions` as a
  comma-separated list). The verifier's `circuit_proof_system_values` and
  `circuit_id_values` are matched against them when present; a circuit that
  declares `functions` is only offered for requests using those. A match
  carries no claims. `ProfilePolicy::with_context` supplies the request context.
  The picker emits rows from the plan, each marked as an unverified request, and
  `metadata.circuit_zk` carries the chosen circuit and plan. (#40)

### Changed

- FFI, **regenerate bindings**: `FfiMatchedCredential` gains
  `circuit_zk: Option<String>`; new `match_dcql_with_context(blob, dcql_json,
  client_metadata_json)`; new `SirosBlobBuilder.add_circuit_zk_system`.
  `match_dc_api_request` and `match_dcql` are unchanged in signature, and
  `match_dcql` now accepts a `circuit_zk` query whose `claims` is an object.
- The registered profile gained a `circuit_zk` format rule, so the committed
  golden blob changed (profile content only; `db::VERSION` is unchanged and a
  blob without the rule still decodes and simply declines the format).

## v0.7.0 — 2026-09-19

Closes the production-readiness review: nine findings, all fixed. The FFI
records gained fields, so a consumer must regenerate its bindings — UniFFI
checksums them against the library at load, and a stale copy fails there
rather than at build time.

### Changed

- Release tags publish the Android AAR to Maven Central as well as GitHub
  Packages (`org.siros:siros-dc-matcher`), so a consumer of the SIROS SDK
  needs no GitHub Packages token for this crate. 0.6.2 was backfilled.

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

  Only string reasons are shown. §6.2's integer and object forms are
  machine-readable purpose identifiers, and putting one on a consent screen
  renders `{"id":7,"name":"Age verification"}` under the list of attributes
  about to be disclosed — verified on a Pixel, and worse than saying nothing.
  Those still reach the application through the FFI, where a lookup is
  possible.
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
