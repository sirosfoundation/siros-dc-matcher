# The `zkp_req` core

`siros-zkp-req` and `siros-zkp-req-nym-auth` are one implementation of the `zkp_req` protocol
layer and of the nym_auth function catalogue, for the matcher, the wallet hosts and the verifier.
They implement the draft of the nym_auth rulebook repository at commit `e65861c`:
`zkp_req.md` (0.1), `nym_auth_rulebook.md` (0.5), `systems/longfellow-nym_auth-v1.md` and
`systems/vega-nym_auth-v1.md`. The BBS-CD system is outside this version.

`siros-zkp-req` holds no prover. The zk-cred repositories hold the provers and the witness
builders; `proving/siros-zkp-backend-longfellow` and `proving/siros-zkp-backend-vega` put them
behind the nym_auth prover interface and the rulebooks' artifact pins.

## Crates

| Crate | Holds | Rust |
| :-- | :-- | :-- |
| `siros-zkp-req` | The protocol: the Credential Query with `_req` and `_req_sets`, `vp_formats_supported.zkp_req`, the usable pair of Section 1.3, the consent model, `ZkpPresentation`, the backends' `Proof`, the `vp_token`, the Verifier's steps 1 to 5 of Section 4.1. Depends on `siros-codec`, `serde` and `serde_json`. | 1.82 |
| `siros-zkp-req-nym-auth` | The catalogue (`pseudonym`, `age_check` with E and C), `verifier_id`, the Longfellow and Vega systems, the session binding, the request policy. With the default feature `credential`: the nym_auth form of an mdoc, the Wallet's credential tests, the presenter, the prover interface and the verifier (`siros-mdoc` with `crypto`, `zeroize`). With `request`: the nym_auth request of `siros-oid4vp`'s verified request. With `test-fixtures`: a test issuer, requests and a test host. | 1.82 |
| `siros-dc-matcher-core` | The matcher. It plans `zkp_req` with the two crates above, without `credential`. | 1.82 |
| `siros-dc-matcher-ffi` | Module `zkp_req`: the presenter and the verifier for Kotlin and Swift (UniFFI), around a host's prover. | 1.88 |
| `siros-zkp-backend-longfellow` | `urn:circuits:longfellow:nym_auth:v1` on `longfellow-libzk-v1`: `LongfellowProver` and `LongfellowVerifier` over zk-cred-longfellow. | 1.95 |
| `siros-zkp-backend-vega` | `urn:circuits:vega:nym_auth:v1` on `vega-v1`: `VegaNymAuth` over zk-cred-vega. | 1.95 |
| `siros-zkp-req-wasm` | The presenter for the browser, with both backends (`wasm-bindgen`). | 1.95 |

The last three and the real-proof tests in `proving/e2e` form the `proving/` workspace. zk-cred-longfellow and zk-cred-vega are edition
2024, which Cargo 1.82 cannot read; in the root workspace they would stop every 1.82 build,
the matcher's included. The matcher plans with the nym_auth catalogue and compiles no prover.

The matcher decides which credentials can serve a query. Signing and proving follow the user's
consent. Every `zkp_req` rule has one owner: the matcher, the FFI and the browser module call the
same functions.

## Flow

```
Wallet presenter                          host (WalletContext)          prover (a backend)
──────────────────────────────────────    ──────────────────────────    ──────────────────
match_query(query, client_metadata,   ←   credentials, anchors, now
            credentials, systems)
  → candidates, or the refusals
                    the wallet's one consent screen
policy::check_request(request object) →   Session (Handover, verifier_id)
prepare(candidate, …, session, seed)
  → data_to_sign, key_id              →   sign(kid, "ES256", data)
job(device_signature) → ProofJob      ─────────────────────────────→    prove(job)
assemble(ProofOutput)                 ←─────────────────────────────    zk_proof, pseudonym
  → ZkpPresentation
vp_token_json / vp_token_cbor

Verifier: verify(query, client_metadata, session, presentation, now, tolerance,
                 trust anchors, NymAuthProofVerifier) → system, results
```

Each phase checks its inputs again: `prepare` repeats `match` for the candidate, `job` verifies
the device signature under the MSO's device key, and `assemble` accepts only the catalogue's
pseudonym and a `zk_proof` of the backend's length.

## The prover interface

`siros_zkp_req_nym_auth::prover` defines a system's prover and verifier. The two backend crates
implement it; a host with its own zk-cred binding, such as the Kotlin SDK, implements it through
the FFI.

```rust
pub trait NymAuthProver {
    fn prove(&self, job: &ProofJob) -> Result<ProofOutput, ProverFailure>;
}
pub trait NymAuthProofVerifier {
    fn verify(&self, statement: &Statement, pseudonym: &[u8; 32], zk_proof: &[u8])
        -> Result<(), ProofFailure>;
}
```

**Input: `ProofJob`.** The presenter builds it from a `UsableAttestation`, the `OpenedSeed` of
its `ssc` and a device signature that verifies under the MSO's device key. It gives `statement`
(below), `issuer_signed` (the credential's `IssuerSigned` as issued), `secret_seed` (16 bytes,
zeroed on drop) and `device_signature` (`r ‖ s`).

**`Statement`**, the public values of system rulebooks Section 4. The Wallet and the Verifier
build it independently; equal statements are the binding.

| Field | Value | Longfellow (Section 4) | Vega (Section 4) |
| :-- | :-- | :-- | :-- |
| `system`, `proof_backend` | the pair of the candidate | selects the circuits | selects the circuits |
| `doc_type` | `eu.europa.ec.eudi.nym_auth.1` | a circuit constant | values 7 to 12 |
| `issuer_certificate`, `issuer_key` | `inputs.issuer_key_set[0]` and its P-256 key Q | signature slots 1, 2 | values 0, 1 |
| `proof_time` | T, `inputs.proof_time` | hash slots 1–160, 20 ASCII bytes | value 4, YYYYMMDDhhmmss |
| `earliest` | E, or `None` | hash slots 161–240, `YYYY-MM-DD`; `0000-00-00` for `None` | value 2, YYYYMMDD; 0 for `None` |
| `cutoff` | C, or `None` | hash slots 241–320, `YYYY-MM-DD`; `9999-12-31` for `None` | value 3, YYYYMMDD; 99991231 for `None` |
| `verifier_input` | `SHA-256(verifier_id)` for `known-offender-matching-ssc` | hash slots 321–576 | values 13 to 15 |
| `session_transcript` | the encoded `SessionTranscript` | seeds the Fiat-Shamir transcript | unused |
| `challenge_digest` | e2 | signature slots 3–258 | values 5, 6 |

**Output: `ProofOutput`.** `zk_proof` in the backend's format (Vega: exactly 96,079 bytes) and
the 32-byte pseudonym the proof establishes. The presenter writes `Proof.inputs`
(`issuer_key_set`, `proof_time`) from the statement; the prover returns only these two values.

**Failures.** `ProverFailure`: `CredentialForm` (the system's `credential_form` code: the
credential lies outside the form of Section 2), `Cancelled`, `Unavailable`, `Failed`.
`ProofFailure` of the verifier: `Encoding` (`proof_encoding`), `Invalid` (`proof_invalid`),
`PublicInput` (`public_input`), the three codes of Section 9, and `Internal`
(`verifier_internal`): the verifier failed on its own inputs, artifacts or code.

## The backends

| Outcome | Longfellow (zk-cred-longfellow) | Vega (zk-cred-vega) |
| :-- | :-- | :-- |
| `credential_form` | `Credential` | none: `Input` and `Refused(Credential)` also hold other causes |
| `proof_encoding` | `ProofEncoding` | `ProofEncoding` |
| `proof_invalid` | `Verification` | `ProofInvalid`: tests 1 and 2 |
| `public_input` | none: the Verifier builds every public input | `Mismatch`, or a pseudonym that differs from `results`: test 3 |

Every other error is `ProverFailure::Failed` or `ProofFailure::Internal`.

The host fetches the circuit artifact. Each backend checks it against the pin of its system
rulebook's Section 8 (`NymAuthSystem::circuit_artifact`) before it decompresses it; zk-cred then
checks the content against its own pin. `proving/scripts/fetch-artifacts.sh` downloads both
artifacts from their reference copies.

| System | Artifact | Bytes | SHA-256 |
| :-- | :-- | --: | :-- |
| Longfellow | `circuits.zst` | 395,608 | `6c4b96ed…5c3b` |
| Vega | `shapes.zst` | 361,395 | `b457ba53…b4df` |

## API

### Rust

* `presenter::match_query(&MatchInput)`: `Match::Candidates`, `Rejected` (per credential, with
  the Section 9 codes), `Unsupported` (per option and system) or `Invalid` (the request rule).
* `catalogue::NymAuthQuery::from_query(ZkpReqQuery)` gives `Catalogued::NymAuth` for a query
  that follows the catalogue, `Catalogued::OtherType` for another credential type, or the
  `CatalogueRule` it breaks.
* `attestation::UsableAttestation::new(data, anchors, proof_time)` reads a stored credential and
  runs the tests of system rulebooks Section 7, step 1. `Unusable` carries the Section 9 codes of
  the failed tests. `attestation::OpenedSeed::open(credential, &SecretSeed)` requires
  `SHA-256(secret_seed) = ssc`; `prepare` opens it again for each presentation.
* `policy::check_request(request_object, signed, channel)` and `CheckedRequest::handover(jwk
  thumbprint)`, with `VerifierId::x509_san_dns(&ClientId, Intermediary)` or
  `VerifierId::semantic(&SemanticIdentifier)`, give the `Session`.
* `request::NymAuthRequest::new(&VerifiedRequest, VerifierIdForm)` (feature `request`) gives the
  `Session` of a verified request that is signed (`openid4vp-v1-signed` over the DC API),
  trusted, asks for an encrypted response and carries no registration certificate, or the
  `RequestRefusal`. Its `verifier_id` is the Client Identifier, or `semantic_id:` and the
  access certificate's semantics identifier: under a WRPAC natural-person policy its
  `serialNumber`, under a legal-person policy its `organizationIdentifier` (ETSI TS 119 475,
  Clauses 5.1.3 and 5.1.5; TS 119 411-8).
* `NymAuthQuery::options()` gives each option; `NymAuthOption::pair(formats, system, date)` gives
  its `UsablePair` or the `PairRefusal` of Section 1.3.
* `attestation::UsableAttestation::of(mdoc, anchors, proof_time)` tests an mdoc `siros-mdoc`
  parsed.
* `presenter::Answer::new(pair, attestation, secret_seed)` holds when the seed opens `ssc` and the
  option's assertions hold.
* `presenter::prepare(&ProveInput)` gives `Prepared`: `data_to_sign`, `key_id`, `statement`,
  `job(device_signature)`, `assemble(&ProofOutput)`, and `prove(device_signature, prover)` for
  a linked prover. `presenter::present` runs the phases with a `Signer` and a `NymAuthProver`.
* `LongfellowProver::load(circuits_zst)`, `LongfellowVerifier::load(circuits_zst)` and
  `VegaNymAuth::load(shapes_zst)` are the backends.
* `siros_zkp_req::vp_token_json` and `vp_token_cbor` build the `vp_token`.
* `verify::verify(&VerifyInput, &dyn NymAuthProofVerifier)` gives `Verified` or a `Rejection`
  with its Section 9 code. `verify::check_presentation` runs the structural checks alone.

### FFI (Kotlin, Swift)

`zkp_req_match`, `zkp_req_session` (→ `FfiSession`), `zkp_req_jwk_thumbprint`,
`zkp_req_prepare` (→ `FfiPrepared` with `data_to_sign`, `key_id`, `statement`, `job`,
`assemble`), `zkp_req_vp_token_json`, `zkp_req_vp_token_cbor`, and `zkp_req_verify` with a
host-implemented `FfiProofVerifier`. `ZkpReqError` carries the request's `error_code`
(`invalid_request`, `access_denied`) and a stable `code`. Indexes are `u64`.

### Browser

`wasm-pack build proving/siros-zkp-req-wasm --target web`, for a desktop browser. Exports
`ZkpProvers` (`loadLongfellow(circuitsZst)`, `loadVega(shapesZst)`, `systems()`), `matchQuery`,
`session` (→ `ZkpSession`), `prepare` (→ `ZkpPrepared` with `dataToSign`, `keyId`, `statement`,
`prove(provers, deviceSignature)`) and `vpTokenJson`. It proves on one thread: no Web Worker
pool, no cross-origin isolation. Objects use the snake_case names of `@sirosfoundation/zkp-req`;
bytes are `Uint8Array`. A refusal throws `{error_code, kind, code, errors?}`. Verification is
available in Rust and through the FFI.

Built with wasm-pack 0.15.0 and wasm-opt 116, the module is 2,896,001 bytes (772,160 with brotli
at quality 11) and its JavaScript glue 31,300 (6,097). It links zk-cred-longfellow under MPL-2.0, part of it derived from Google's
longfellow-zk under Apache-2.0; a page that serves it carries their notices.

## The frontend package

`@sirosfoundation/zkp-req` (wallet-frontend, `packages/zkp-req`) defines the wallet's side:
`ZkpReq` runs `match`, the consent screen and `prove` across queries, and a host
(`ZkpPresenterInPageHost`, `ZkpPresenterNativeWrapperHost`) runs a `ZkpPresenter`. Its in-page
host creates a mock presenter; `create_zkp_presenter(wallet)` over `siros-zkp-req-wasm`
replaces it:

* `match(req)`: `wallet.credentials`, `wallet.anchors` and `wallet.now`, then `matchQuery`;
* `prove(candidate, req, session)`: `session`, `prepare`, `wallet.sign(keyId, "ES256",
  dataToSign)`, then `prove` with the `ZkpProvers` the host loaded once.

The native wrapper host reaches the same functions through the FFI, with the zk-cred prover the
app ships. To follow the draft, the
package's types change in these places:

* `ZkpFormats` holds `proof_backend_values` and `system_id_values`, both required
  (Section 1.2).
* `Candidate` names `proof_backend` and the option: `req_set` and its `_req` indexes `items`.
* `ZkpPresentation` holds `system_id`, `proof_backend`, `req_set` when the query has
  `_req_sets`, `proof` and `results`. `issuer_key_set` and `proof_time` are members of
  `Proof.inputs`. `prove` returns the encoded presentation, so `vp-token.ts` only wraps it;
  its encoder writes `proof_time` with milliseconds, and the systems require the 20-character
  form.

## Acceptance gates

* **G1, honest path** (`tests/flow.rs`, `tests/zkp_req_api.rs` of the FFI). For each system
  (`urn:circuits:longfellow:nym_auth:v1` on `longfellow-libzk-v1`,
  `urn:circuits:vega:nym_auth:v1` on `vega-v1`): a request is matched, the test host signs the
  data to sign with a P-256 device key and runs a test prover, the presenter assembles the
  presentation, ciborium reads it with the draft's structure, and the Verifier accepts it. The
  pseudonym equals `SHA-256(DST ‖ secret_seed ‖ 0^32 ‖ SHA-256(verifier_id))`, written out in
  the test.
* **G1 with real proofs** (`proving/e2e/tests/real_proofs.rs`, ignored: run with `--release`
  after `proving/scripts/fetch-artifacts.sh`). For each system the backend builds the witness
  and proves, and the Verifier with the same backend accepts; once with `age_check` `18+`, once
  with `0-2025`, whose E lies in year 0000.
* **G2, differential** (`tests/readdit.rs`). readdit 1cf3f26, the reference code of the system
  rulebooks' Section 10, reads a credential of the test issuer in a redirect session. For both
  systems, this crate reaches readdit's mdoc fields, issuer key, `SessionTranscript`, data to
  sign, e2, `verifier_input` and pseudonym. readdit's v0.4 presentation maps onto the draft's:
  `issuer_key_set` and `proof_time` move into `Proof.inputs`, `proof` becomes
  `Proof.zk_proof`, and `proof_backend` is new.
* **G3, refusals** (`tests/refusals.rs`). One table holds one fixture per refusal rule: the
  request rules (`invalid_request`), `vp_formats_not_supported`, the Wallet codes of the system
  rulebooks' Section 9, and the Verifier's codes. Each row asserts the exact typed error.
* **G4, known answers** (`tests/known_answers.rs`). The `age_check` examples of the specs, the
  29 February cases worked by hand from the catalogue's rule, and the pseudonym and session
  vectors the provers ship.
* **G5, tamper** (`tests/flow.rs`). A changed public input, a changed result and a presentation
  for another request each reach the proof check and are refused there. With real proofs: a
  presentation for another session is `proof_invalid` with Longfellow and `public_input` with
  Vega, and a `zk_proof` one byte short is `proof_encoding` with both.
* **G6, build.** `matcher.wasm` within its budget, Kotlin and Swift bindings generated,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings` and
  `cargo fmt --all -- --check` clean in both workspaces, the picker crates on Rust 1.82, and the
  browser module importing only wasm-bindgen's modules.

## Licence

BSD-2-Clause, as the rest of the repository. `session.json` and `pseudonym.json` come from
zk-cred-vega (BSD-2-Clause). `readdit.json` holds values readdit computed; readdit's code stays
upstream. The backends depend on zk-cred-longfellow (MPL-2.0) and zk-cred-vega (BSD-2-Clause).
