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
commit `e65861c`), and adds the components of the SIROS wallet core. **Breaking**: requests and
presentations follow the draft, the DCQL parse enforces OpenID4VP 1.0, Section 6, the FFI loses
`zkp_req_plan`, and the vectors move to the crates that own their rules. Consumers that keep a
copy of the vectors (siros-sdk-kotlin, siros-sdk-swift) must re-copy them from the new
directories; the vector set digest below identifies them. `matcher.wasm` is 358,122 bytes, over
the 307,200-byte budget (303,418 at v0.11.0), sha256
`3778393e7909806c6cfdfd486f87329d1a3b42f57fabc17f2c6d6b6fee10f3c6` with Rust 1.99.1 and binaryen version_116.

### Changed

- The matcher crate `siros-dc-matcher-wasm` is `siros-picker`, and its test host
  `siros-dc-matcher-testhost` is `siros-picker-testhost`. `make matcher` builds `matcher.wasm`
  as before.
- The error types of siros-registration, and those this release changes in android-credman,
  siros-credential, siros-display, siros-oid4vp, siros-presentation and
  siros-transaction-data, derive `thiserror::Error`. Each `Display` text is unchanged, and
  `source` gives the cause an error wraps.
- `siros-picker-testhost` refuses a null pointer for a required string, a string without a NUL
  or of no UTF-8, a null image with a length, and a negative read. It captures an entry's
  `metadata` and a field's value as `None` for a null pointer.
- `make matcher` runs `wasm-opt -Oz` of binaryen version_116 after the strip, and refuses
  another version; `make wasm-opt` installs it (the `wasm-opt` crate 0.116.1). The release's
  `matcher.wasm.sha256` and its notes name the binaryen beside the rustc.
- **BREAKING (matcher):** `matcher.wasm` is the credential picker of the wallet core (K1 to
  K4). It reads the registration siros-registration writes, parses the request into
  `UnverifiedRequest`, and runs the presentation component's matching over it: the matching of
  the wallet's plan, issuers admitted by the TR5 facts at the time of registration, and the
  transaction data selection over the projected definitions, with the K2 exceptions. A wallet
  registers the projection in place of the v1 blob, which the picker no longer reads. Each
  offer is the set `siros-{offer}`, an entry's `cred_id` is the `credentialId`, and the
  standard object's `data` is the pick `{"offer", "query", "credential"}` that
  `Planned::picked` maps to the wallet's selection. An entry's fields are its claim rows, then
  the displayed claims of the transaction it takes. An entry's title, subtitle and icon are the
  registered card's title, issuer line and icon. A credential that takes an entry of a
  payment rulebook (the EC TS12 v1.0.1 payment type, PaSO Payment) is a payment entry: payee,
  amount, and at host level 3 the `additional_info`; its payment method icon is the card's
  icon, and its bank and provider icons are NULL. An absent disclaimer or warning is NULL, and
  each set id is declared once per invocation. A diagnostic entry shows the wallet's default
  icon. An offer that breaks the presentation component's guarantees (a member without a
  candidate, a query or candidate its matching lacks, a proof answer without its option)
  panics: the picker emits nothing. At host level 7 each entry carries its offer's
  delegation: `Full` for an offer that needs no wallet display (A9), else none. The picker
  reads no calling app origin. `mso_mdoc_zk` matches nothing.
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
  documents the host ABI. `Picked::parse` reads the standard object of the entry the host
  returns, and `SetEntry::shown` whether the host shows an entry whole (`Shown`).
- Below host level 2 the matcher emits nothing; it used to call the
  `credman_v2` functions regardless.
- On level 2 and above, the matcher emits nothing when the host's inputs are
  malformed: a read that reports more bytes than it wrote. It used to emit
  entries from such inputs.
- The registered blob is read until complete; a short
  `ReadCredentialsBuffer` read used to leave its tail zeroed.
- `siros-dc-matcher-core`'s unused `sink` module is removed.
- Entry metadata is the standard object
  `{"display_skipped":bool,"host_level":n,"data":{…}}`. The matcher's own
  members moved under `data`; `host_abi` became `host_level`.
- A NUL inside a picker string becomes a space; it used to end the string.
- **BREAKING (Rust API):** `siros-dc-matcher-core`'s `request` module is `siros-oid4vp`'s
  `UnverifiedRequest`, which holds the request's parsed `DcqlQuery`. An entry reads only under
  the three protocols of OpenID4VP 1.0, A.1; a profile label outside them reads as no protocol.
  `UnverifiedRequest::first_registered` and `diagnose` take the registration as a label
  predicate. `ProfilePolicy::with_context(&RequestContext)` is
  `ProfilePolicy::with_client_metadata`, which takes the request's `client_metadata`, the lists a
  `zkp_req` query is matched against; the query's `_req` and `_req_sets` are extension members of
  its DCQL `CredentialQuery`. `first_supported_request` and the entry predicate are removed. The
  public modules `base64url` and `purpose` are removed: siros-codec's `base64url` and
  siros-display's `purpose` hold them. `DecodeError::Malformed` is `Truncated`, `Syntax`, `Shape`
  or `TooDeep`.
- **BREAKING (Rust API):** `siros-dcql` 0.12.0 constructs a query only by parsing, one pass over its
  JSON value: its fields are private, read through accessors, and `DcqlQuery::validate` is gone. The
  parse enforces OpenID4VP 1.0, Section 6. It refuses a member of the wrong JSON type, `null`
  included, and an absent REQUIRED member, `meta` among them; an empty `credentials`, `claims`,
  `claim_sets`, `credential_sets`, `options`, `credential_sets` option, `trusted_authorities` or
  `values`; a `values` element other than a string, an integer or a boolean; an id outside the
  characters of Sections 6.1 and 6.3, or repeated; a claims query without `id` in a Credential Query
  with `claim_sets`; `claim_sets` without `claims`; a `claim_sets` or `credential_sets` option
  naming an unknown id; a claims path that is no claims path pointer; and an `mso_mdoc` claims path
  other than two strings. Ids are `QueryId`s and `ClaimId`s, a claims path is a `ClaimPath`,
  `trusted_authorities` is a `TrustedAuthorities`, and `multiple`,
  `require_cryptographic_holder_binding` and `required` are enums. A Credential Query keeps its
  other members as extension members (`CredentialQuery::extension`), and `CredentialQuery::parse`
  reads one alone. A claims path processing error other than an empty selection reaches the caller
  (`select_claims`, `QueryMatch::refusals`), and `DcqlQuery::from_json` refuses with a
  `QueryTextError`. See [its changelog](crates/siros-dcql/CHANGELOG.md).
- **BREAKING (FFI):** `match_dcql`, `match_dcql_with_context` and `match_dc_api_request` fail
  with `MatchError::Request` for a query the DCQL parse refuses, as listed above: among them a
  Credential Query without `meta`, a malformed `trusted_authorities` (`[{"type": "aki"}]` or
  `[]`), a `null` member, an empty `claims`, and an object under `claims`, a `zkp_req` query's
  included. v0.11.0
  matched such a query: for the mDL fixture under a malformed `trusted_authorities`, its
  `match_dcql` gave `Ok` with `satisfiable: true` and one combination, and a `zkp_req` query
  with an object under `claims` gave `Ok` with `satisfiable: false`.
- **BREAKING (matcher):** `matcher.wasm` emits nothing for a request whose DCQL query the parse
  refuses, the same queries as the FFI above. Observed with the test host on the mDL fixture:
  under `trusted_authorities` `[{"type": "aki"}]` or `[]`, the matcher at `1b0fe3d` emitted the
  one entry of set `siros-0`, and this build emits nothing. An `aki` value that is no
  base64url changes nothing: the matcher resolves no `trusted_authorities`, and both emit the
  entry. A debug build names the parse error in its one entry, in set `siros-debug-request`.
- Vector set digest: `db62a22cfaccb912bf717c63d2a107e41e5437caa72e21594ceb3bb395eab431`.

### Fixed

- `matcher.wasm` v0.8.0 to v0.11.0 imported `wasi_snapshot_preview1.random_get`,
  which the host lacks, and trapped on `zkp_req` requests. `siros-dcql` finds repeated ids with
  rustc-hash's `FxHashMap`, which takes no seed, and the `zkp_req` crates use no seeded
  collection.

### Added

- `siros-codec`, the encodings every wallet core crate shares: a strict CBOR reader (definite
  lengths, no duplicate keys, no trailing bytes, at most `cbor::MAX_DEPTH` (32) levels) and a
  deterministic writer; unpadded base64url and the padded base64 of `x5c` certificates (RFC
  4648, Sections 4 and 5); the calendar dates and UTC times of CBOR's `full-date` and `tdate`;
  the ES256 signature value (`signature::Es256Signature`); an `https` URL (`url::HttpsUrl`);
  and `json::JsonTextError`, what
  serde_json reports of text that is no JSON. With the feature `json` it holds the strict JSON
  reader, `Json::parse_unique`: one value, members in document order, each member name once per
  object, every number with the text its writer chose (`JsonNumber`), at most `json::MAX_DEPTH`
  (64) levels. It refuses with a `JsonFault`: a text fault anywhere in the bytes comes first,
  then the first, in document order, of a number beyond binary64, nesting too deep and a member
  name an object repeats. `siros-wallet-state`
  reads the wallet state with its own reader, where a repeated name keeps its last value, as
  `JSON.parse` in `wallet-frontend` does. The crate holds the internals the components share:
  `member::MemberFault` with its `ArrayIndex`, `chain::CertificateChain` (the DER chain an mdoc
  `x5chain` and an `x5c` carry), the `position!` and `text_value!` macros that declare value
  newtypes, and `display_code!`, which shows an error by its stable code.
- `siros-mdoc`, ISO/IEC 18013-5 mdocs: the stored credential, element selection, the
  `DeviceResponse`, and the device signature's signing input (`device_signing_input`, a
  `SigStructure` whose `digest` the device key signs). Names and values are types: `DocType`
  (siros-dcql's), `NameSpace`, `ElementIdentifier`, `DigestId`, `ItemDigest`, `CoseAlgorithm`,
  `SigStructure`, `MessageDigest` and `SessionTranscript`. `IssuerAuth::x5chain` gives the whole
  `x5chain`, the Document Signer's certificate first, and `P256Key` reads an uncompressed point.
  Every `MdocError` carries its fault.
- `siros-sdjwt`, SD-JWT VC: the stored credential with its issuer JWT's `x5c` (`SdJwt::x5c`),
  disclosure selection over `ClaimPath`s (`SdJwt::select`), and the presentation with its KB-JWT
  signing input: `Presentation::key_binding` takes a `NumericDate`, an `Audience` and a
  `KbNonce`, and `KeyBinding::assemble` an `Es256Signature`. Its JSON parts read with
  siros-codec's strict reader. Every `ParseError` carries its cause: `IssuerJwtFault`,
  `DisclosureFault` with the disclosure's `DisclosureId`, `SdAlgFault`, `ReservedFault`, the
  repeated `Digest`, the misplaced disclosure with its `Placement`, the existing claim name, the
  unreferenced disclosure, and `X5cError` with the certificate's `X5cIndex`. A part nested
  deeper than 64 levels is a JSON fault of that part; `claims_too_deep` covers 33 to 64 levels.
  `KeyBindingError` is `RequiredClaim` or `RepeatedClaim` with the name.
- `siros-credential`, the format-independent credential: typed claims read by `ClaimPath`,
  validity (`UsableCredential::time`), `credential_type()` (a `CredentialType`: `Vct` or
  `DocType`), `issuer()` (an `IssuerIdentifier`), `configuration_id()` (a `ConfigurationId`),
  and `holder_key()`, the holder's P-256 key: an SD-JWT VC's `cnf.jwk` or an mdoc's
  `deviceKey`. An SD-JWT VC without a P-256 `cnf.jwk` does not parse
  (`CredentialError::HolderKey`, with the coordinate and its fault); `CredentialError` names
  the `RegisteredClaim` and the `CborTag` it refuses. `least_used` chooses the instance of a
  batch (C5). With the feature `chain`, a credential parses with its issuer chain (TR2): the
  mdoc's `x5chain`, or the issuer JWT's `x5c`; a chain that does not parse is
  `CredentialError::IssuerChain`, and `Credential::issuer_chain` gives it. `ClaimTree` holds a
  credential's typed claims without its signatures, minus named members, and reads and writes
  them as CBOR: an mdoc full-date and date-time keep their tags, a JSON number its text, and a
  withheld array element its position (`TreeError`). `ClaimSource` reads the claims of a
  `Credential` or a `ClaimTree` by `ClaimPath`. `EntryRef::new` builds an entry reference.
- `siros-wallet-state`, the decrypted wallet state `S` of the private data container
  (privatedata 3.1, Section 6): `WalletState::parse` reads versions 3 and 4 into its credential
  entries with their `metadata`, each value as its exact text, its presentation records and the
  `kid` of each key pair. A repeated member name keeps its last value, as `JSON.parse` in
  `wallet-frontend` does. A refusal is a `WalletStateError` with its cause: the `JsonTextError`
  of a member of another JSON type (`ArrayFault`, `MetadataFault`, `TypeFault`,
  `PresentationsFault`). `PresentationRecord::new` gives the record the host appends as a
  `new_presentation` event (H5). `CredentialId::new`, `BatchId::new` and `InstanceId::new` are
  public, for the entry references the picker registration carries; `IssuerIdentifier::parse`
  and `ConfigurationId::parse` refuse the empty string (`EmptyIdentifier`).
- `siros-display`, display for the wallet core: display metadata, credential cards (`Card`, with
  its `Colour`s and `Logo`), claim rows, purpose lines, and proof statement rows
  (`proof::verified_rows`, each a `DisplayText` label and value held whole). One locale function,
  `lookup`, takes the entry of every display array for the wallet's one language, a `Locale` the
  host gives: RFC 4647 Lookup, then the entry without `locale` (PaSO View, Section 4). A card's
  title and a claim's label come from the Type Metadata, else, for a language it has no entry for,
  from the configuration's `credential_metadata` (OpenID4VCI 1.0, Section 12.2.4). A card's title
  and issuer line are `CardText`, labels with a character other than white space: the display
  entry's name and the Credential Issuer's display name, else the host's `CardFallback` in the
  wallet's language (the owner's wallet's `displayTitleFallback` and `displaySubtitleFallback`).
  `DisplayCache` keys Type Metadata by siros-dcql's `Vct` and issuer metadata by
  siros-wallet-state's `IssuerIdentifier` and `ConfigurationId`, and gives a credential's issuer
  metadata (`DisplayCache::issuer_metadata`). A `DisplayError` carries its cause: a colour that is
  no numerical colour value of CSS Color Module Level 3 holds its `ColourFault`. Without the
  default feature `credential` it holds what the picker links: purpose lines, proof statement
  rows, `ClaimLabels`, the labels of a credential's claims that `DisplayCache::claim_labels` gives
  and that give the rows of any `ClaimSource`, and `Field`, a picker field whose name and value
  are fitted to `FIELD_MAX` (80) characters, its `Extent` known when it is made. Display text
  refuses the characters of Unicode 16.0's general categories Cc, Cf, Zl, Zp, Co and Cn, from a
  table of 736 ranges.
- `siros-oid4vp`, OpenID4VP 1.0 for the wallet core. Without `crypto` it holds the picker's
  request reading (`UnverifiedRequest`, `diagnose`, `NoQuery`, whose `Malformed` holds the
  `QueryError`), `ClientId`, whose parse refuses with a `ClientIdError`, the `Fetch` effect, and
  what transaction data reads of a request (`RequestSignature`, `ResponseMode`,
  `TransactionDataItem`), and builds with Rust 1.82. `UnverifiedRequest` carries the request's
  `transaction_data` entries, read by the rule intake applies (`TransactionDataItem::list`,
  `NoQuery::TransactionData`), whether it arrived signed, its Response Mode and the formats of
  its `verifier_info`. With `crypto`: sans-IO intake of redirect
  requests (by value, `request`, `request_uri` with `get` or `post`) and DC API requests
  (unsigned, signed, multisigned) into a `VerifiedRequest`, with `Fetch` and `Trust` effects for
  the host (a `Fetch` states the most redirects it follows, `Fetch::redirects`); the Client
  Identifier Prefixes `x509_san_dns`, `x509_hash`, `decentralized_identifier`,
  `verifier_attestation`, `openid_federation` and `redirect_uri`; ES256 Request Objects; the
  `vp_token` (`VpToken::json`), its submission per Response Mode, `ECDH-ES` response encryption
  with `A128GCM` or `A256GCM`, error submissions, and the reply to a direct post.
  `direct_post.cwt` (`zkp_req.md`, Section 6.2) posts the CBOR Authorization Response in a
  `COSE_Encrypt` by ECDH-ES + HKDF-256 with `A128GCM`, `A192GCM` or `A256GCM`. `Handover` and
  `ec_jwk_thumbprint` give the session transcript's handover, with `None` for the CBOR `null` of
  an unencrypted response (B.2.6). `VerifiedRequest::access_certificate` gives the
  `CertificateDer` and the `SemanticIdentifier`, or the `SemanticIdError`, of an `x509_san_dns` or
  `x509_hash` signer's certificate: the WRPAC policy (ETSI TS 119 411-8) says whether its subject
  is a natural person, identified by its `serialNumber`, or a legal person, identified by its
  `organizationIdentifier` (ETSI TS 119 475, Clauses 5.1.3 and 5.1.5). `dc_api_protocol` gives the
  DC API protocol, `signature` whether the request arrived signed (`RequestSignature`), and
  `verifier_info_formats` the `AttestationFormat` of each `verifier_info` attestation (Section
  5.1). Each refusal is an `IntakeError` with its cause: the `QueryError` of a `dcql_query`, the
  `JsonTextError` of a parameter or a DC API request that is no JSON, the `Utf8Error` and
  `der::Error` of what does not decode, the `VerifierInfoRule` a `verifier_info` breaks, the
  `LeafKeyFault` of an `x5c` leaf key, the `ClaimsFault` of a Verifier Attestation's claims, and
  the `JwkFault` of a JWK that is no P-256 key: the host's resolved key (`ResolvedKeyInvalid`),
  or, when no `ECDH-ES` encryption key of `jwks` is usable, the first that names P-256
  (`EncryptionKeyInvalid`). A key that does not read is passed over, as a key of another type or
  curve is (RFC 7517, Section 5).
- `siros-transaction-data`, the `transaction_data` request parameter (OpenID4VP 1.0, Section
  5.1) for the wallet core, on the PaSO model (draft 2), with the four EC TS12 v1.0.1 types as
  built-in rulebooks. It builds with Rust 1.82.
  - One definition form, a PaSO `transaction_data_types` entry (Proof Metadata, Section 3):
    `Definition` with its `ClaimDefinition`s (`PayloadPath`, `Mandatory`, `ValueType` with
    `template:`) and `UiLabels`. A label is a `LabelText` of its `LabelRole`; its source sets
    its `LabelRules`: PaSO's limits in grapheme clusters (Section 3.3), or TS12's in characters
    for the UI elements it names and none for claim names (Section 3.3.3). Labels refuse C0
    controls, DEL, C1 controls, directional overrides and unterminated isolates; a
    `Description` follows the directional rule alone. A `display` entry whose `display_type` is
    no label format leaves its array (View, Section 3). The structural rules refuse with a
    `DefinitionError`.
  - Sources, each a parser into that form. For one entry and credential: the entry's ad-hoc metadata
    JWT (Section 5.3); else the credential's own metadata, its signed credential metadata JWT
    (Sections 4 and 7: ES256 or ES384, an `x5c` chain to the credential's root with its leaf's
    Subject, or a `kid` of the issuer's JWT VC issuer metadata) or the `transaction_data_types` of
    its TS12 type metadata, which declare every type the credential supports (`TypeUndeclared`):
    none outside the SCA category, and the SCA category requires them; else, for a credential known
    to have no metadata of its own, the host's `Configuration`: a `vct` that is no `https` URL and
    that `vct#integrity` does not pin (`Ts12Fault::VctNotHttps`), or Type Metadata without
    `transaction_data_types` or recorded as absent. Type Metadata neither held nor recorded absent
    (`Ts12Fault::NotHeld`), issuer metadata the host does not hold (`IssuerMetadataNotHeld`), and
    signed credential metadata that is not held or not valid exclude the credential for every entry,
    an ad-hoc JWT included; a failed ad-hoc JWT makes its entry incompatible.
  - Metadata is input: `HeldMetadata` holds the signed credential metadata JWTs, Type Metadata
    with the documents it references, and issuer key sets, which the host fetches and renews
    outside presentations, and records a URL whose fetch answered 404 as absent
    (`HeldDocument::absent`); the wallet verifies each every time it loads it, a JWT's
    `credential_metadata_uri` against the URL it was served from (Sections 6 to 8).
    `HeldJwt::verify_fetched` admits a JWT the host fetched and gives its `Renewal`: its expiry
    and the URL to renew from. `HeldMetadata::wanted` lists what the host should hold for a
    credential: issuer metadata, signed credential metadata it lacks or whose JWT no longer
    verifies, and documents neither held nor recorded absent.
  - `Definition::project` keeps the entry of each array the locale function takes, with the
    source and the rulebook; a type with an array it leaves empty is unsupported in that
    language. `Projected::to_json` writes it, additional parameters in the member order of RFC
    8785, and `Projected::parse` reads it back. `Context::served` gives a credential's
    definition of a type.
  - `Entry::parse` reads an entry (T1); `transaction_data_hashes_alg` reads as an array or as
    CS-12's string, and a TS12 rulebook requires it. `check_request` refuses an unsigned
    request with a PaSO-targeted entry (Core, Section 3), and targeted queries outside one
    credential set or alternatives that are not transposable (Section 7.4.1).
  - `Selector::first_match` over a credential's `Definitions`, and `Context::first_match` over the
    wallet's sources, give each candidate credential its first compatible entry (Section 7.4.2): a
    supported type, a conforming payload (`PayloadFault`: `#integrity` companions only beside image
    claims and as strings, a mandatory claim in every element its `null` ranges over and an empty
    array holding none, an `iso_currency_amount` with its minor unit's digits, an image value of
    its form: a base64 Data URL of PNG, JPEG or SVG of at most 512 KiB, or an `https` URL with
    the integrity values of its `#integrity` sibling, which a TS12 logo may lack), at most 200
    items, images the request's `Channel` admits (over the Digital Credentials API, a Data URL of
    PNG or JPEG, the formats Credential Manager shows), and a full rendering (`TransactionView`:
    rows in claims order, `template:` values as `Segment`s of text and typed values; the UI
    checks each label again once formatted). The view carries each image as an `Image` for the
    UI, which resolves the URL, verifies its integrity, holds it to `MAX_IMAGE_BYTES` and
    `MAX_IMAGE_PIXELS`, renders an SVG document statically, and leaves out an image it cannot
    verify; the core fetches and verifies no image content. Under a TS12 rulebook an image the
    channel does not admit is left out (`TransactionView::absent_images`). Every reason an entry
    does not serve a credential is an `Incompatibility`. A PaSO-sourced definition needs a signed
    request; a TS12 type in an unsigned request carries `UnsignedWarning::Required`.
  - The picker's side, without `wallet`: `Selector::first_match_unverified` runs the first match
    over the projected definitions, and gives `Selection::Deferred` with its `Deferral` for an
    entry with an ad-hoc metadata JWT (K2). `ServedTypes` records per
    credential the definition each type is served by, or why it is not (`Unserved`); an
    unserved definition names its `CredentialSource`, a source of the credential's own.
    `Taken::payment` gives the payee and amount of a payment rulebook's entry (`Payment`).
    `grapheme_clusters` counts UAX #29 clusters over a table of 1,117 runs of Unicode 16.0;
    unicode-segmentation is the oracle of a test.
  - `Binding::kb_jwt_claims` gives the KB-JWT claims of the entry a credential binds:
    `transaction_data_hashes` over the entry as received, `transaction_data_hashes_alg` when
    the entry carried it, and under a TS12 rulebook `jti`, `response_mode` and `amr`.
  - Every refusal of a request is a `TransactionDataError`: `invalid_request` for an unsigned
    request, `invalid_transaction_data` otherwise.
  - Without the default feature `wallet` the crate holds the selection over a registration for
    the credential picker: definitions, the projection reader, payload conformance, selection and
    rendering, and links no X.509, ECDSA or trust code. The picker cannot verify an ad-hoc
    metadata JWT.
- `siros-trust`, issuer trust for the wallet core (§4.18).
  - TR1: `TrustStore::parse` reads the host's record, an array of `{type, value, certificates}`
    entries, `type` `etsi_tl` or `openid_federation`, each authority once, with siros-codec's
    strict reader; each refusal is a `StoreError` with its cause (`EntryError` with a
    `MemberFault`, the certificate's `CertificateError`, a member name an object repeats in the
    `JsonFault`).
  - TR2: `IssuerChain::parse` reads a credential's `CertificateChain` with the
    AuthorityKeyIdentifier keyIdentifiers of its certificates; `ChainError` names the
    certificate that does not parse, and `CertificateError` holds its `der::Error`,
    `PublicKeyFault` or `KeyIdentifierFault`. A certificate's issuer and subject are
    `DistinguishedName`s, compared as DER bytes.
  - TR3: `QueryAuthorities::of` reads a Credential Query's `trusted_authorities` (a malformed
    `aki` value is an `AuthorityError`), and `AdmittedIssuer::resolve` admits a credential's
    issuer for one query at a time: the query names no authority, an `aki` value names a key the
    chain's AuthorityKeyIdentifiers name, or the store entry of an `etsi_tl` or
    `openid_federation` value admits the chain. The `AdmittedIssuer` keeps the query's
    `QueryAuthorities`, which `QueryAuthorities::are_those_of` compares with a Credential Query.
    Path validation, `IssuerChain::validate_path`, gives the anchor a chain's path ends at at a
    time, or its `PathRefusal`; `TrustStore::anchor` gives the anchor of the first store entry
    with a path, or `Unanchored` with each entry's refusal. A path is a prefix of the chain, each
    certificate signed by the next, whose last certificate an anchor signs: every certificate on
    it, the anchor included, is valid at the time; each signer's subject is the certificate's
    issuer, the signer is a CA, its keyUsage, when present, includes keyCertSign, and at most its
    pathLenConstraint of non-self-issued intermediate certificates lie below it, a self-issued
    link certificate counting none; each signature is ECDSA P-256 with SHA-256 or P-384 with
    SHA-384 over the `tbsCertificate` as written; and every critical extension on the path is one
    TR3 processes (`extensions`: basicConstraints, keyUsage, extKeyUsage, authorityKeyIdentifier,
    subjectKeyIdentifier). Direct trust: a store certificate byte-identical to the chain's first
    certificate admits it while it is valid. The anchor whose SubjectKeyIdentifier equals the
    certificate's AuthorityKeyIdentifier is tried first.
  - TR5: `IssuerFacts::at` gives the facts the wallet records for the picker, and
    `Admission::of` admits from them alone, with the rule of TR3 (`QueryAuthorities::admit` over
    an `Issuer`).
  - Without the feature `chain` the crate holds the rule, the authorities and the facts, builds
    with Rust 1.82, and links no X.509 or ECDSA code. `StoreType::named` reads a store entry's
    `type`.
- `siros-zkp-req`, the `zkp_req` protocol layer. `ZkpReqQuery::parse` reads a DCQL
  `CredentialQuery`, its `format`, `meta` and the extension members `_req` and `_req_sets`, and
  takes `id`, `multiple` and `require_cryptographic_holder_binding` from it; a `RequestRule`
  carries what breaks it (`MemberFault`, `IdentifierFault`, `ReturnFault`, `OptionFault`,
  `TypeValueFault`). It holds `ZkpFormats` (Section 1.2), the usable pair of a `System` and a
  `ProofBackend` (Section 1.3), `ZkpPresentation` and `ProofEnvelope` with `ProofContent`,
  `ZkProof` and typed keys (Section 4), and the Verifier's steps 1 to 5 (`answered_option`,
  `StructureRejection`, Section 4.1). With the feature `vp-token`, `presentations_of` gives the
  presentations of a query in a JSON `vp_token`, read with siros-codec's strict reader
  (`VpTokenError`). Ids and positions are types: `FnId`, `ReturnHandle`, `SystemId`,
  `ProofBackend`, `ResultKey`, `InputName`, `W3cType`, `ItemIndex`, `ReqSetIndex` and
  `PresentationIndex`. It holds Rust 1.82.
- `siros-zkp-req-nym-auth`, the nym_auth catalogue with the Longfellow and Vega systems, the
  session binding, the Wallet's credential tests, a presenter in phases and the Verifier's
  checks, behind `NymAuthProver` and `NymAuthProofVerifier`. It holds Rust 1.82.
  - Each test of a query or a credential is the constructor of its result.
    `NymAuthQuery::from_query` reads a `ZkpReqQuery` against the catalogue (`Catalogued`:
    `NymAuth`, or `OtherType` for another credential type); its `Item` is an enum whose
    `pseudonym` holds its `return`, and a `CatalogueRule` carries what breaks it (`ParamFault`,
    `ContextFault`, `PrfUndefined`). `TestedAttestation::of(mdoc, proof_time)` runs the
    credential tests, and its refusal `Unusable` carries the Section 9 codes; the `birth_date`,
    `ssc` and `psc` refusals hold a `FullDateFault` or a `CommitmentFault`.
    `UsableAttestation::new(tested, admitted, query)` takes the `AdmittedIssuer` of the same
    Document Signer by the authorities of the same query, its `id` and its
    `trusted_authorities` (N3), and `Answer::new` refuses an attestation admitted for another
    query's authorities. `OpenedSeed::open` opens the `ssc` with the `SecretSeed`.
  - The presenter: `Prepared::new` takes the answer and the request, gives the `SigStructure`
    the device key signs, and proves with its `Es256Signature`; only `Prepared::job` builds a
    `ProofJob`. `NymAuthRequest` (feature `request`) is the nym_auth request of a verified
    request, with the session of its `Handover`: signed by a Request Object or under
    `openid4vp-v1-signed`, trusted, encrypted, and without a registration certificate:
    `policy::signed_and_encrypted` checks these rules on a `PolicyRequest`, a `VerifiedRequest`
    or, in the picker, an `UnverifiedRequest`, whose trust the wallet checks after the pick. Its
    `verifier_id` takes the `VerifierIdForm` of the trust framework: `semantic_id:` and the
    access certificate's semantics identifier, or `x509_san_dns:` and the Client Identifier
    (`VerifierId::semantic`, `VerifierId::x509_san_dns`); a certificate without one is refused
    with its `VerifierIdRule::SemanticId` reason. `check_request` (feature `credential`) takes
    `Signing`, and `CheckedRequest` gives the `client_id` as a `ClientId` and the `nonce` as a
    `Nonce`.
  - The Verifier (`verify`) builds the `Statement` from its own query, session, clock and trust
    configuration. DCQL parses its own query first (`OwnQueryFault::Dcql`). It admits the
    Document Signer by siros-trust's path validation over its `trust_anchors` at its clock: an
    anchor that is expired, is no CA, or carries a critical extension TR3 does not process is
    refused, and an anchor that signs with ECDSA P-384 and SHA-384 admits the Document Signer
    it signs. `Rejection` names its fault (`OwnQueryFault`, `ProofEncodingFault`,
    `ResultsFault`, `IssuerKeySetError::Untrusted` with the `PathRefusal`).
    `NymAuthSystem::circuit_artifact` gives the circuit artifact pins of the system rulebooks'
    Section 8, and `NymAuthSystem::admits_zk_proof` whether a proof has a length the system's
    proof backend reads.
- `siros-presentation`, the presentation component of the wallet core.
  - Phase 1 plans a verified request over the wallet's credentials usable at the plan's time,
    against the host's `TrustStore` (`PlanInput`): the format table, `meta`, holder binding and
    no query but `zkp_req` on a nym_auth attestation (A1); a credential whose issuer the query's
    `trusted_authorities` refuse matches nothing, in every format (TR3), and a candidate carries
    its issuer's admission into the offers and phase 2. `zkp_req` is one selection, then the
    usable attestation and the `secret_seed` delivered in the credential's auxiliary data (A2),
    read with siros-codec's strict reader: a credential without one is excluded with its
    `NoSeed`, an `opening` absent, not a string, not base64url or not 16 bytes each its own.
    Offers, optional additions, an offer per option when every set is optional, and a
    `multiple` member holding every candidate (A3). Transaction data selects by PaSO's first
    match (Core, Section 7.4): a candidate of a targeted query that takes no entry is excluded,
    an entry no presented credential takes stays unused, and an entry of a type no source
    defines refuses the request unless every credential it targets takes an entry (OpenID4VP
    1.0, Section 5.1). `PlanInput` takes the wallet's language, the host's `CardFallback`, the host's transaction data
    `Configuration`, and the transaction metadata the host holds (`HeldMetadata`).
  - The plan also gives the entry each presented credential binds, the credential named by
    `credentialId` and instance (T4); the plan's digest over the request, its trust verdict,
    the nym_auth `verifier_id` and every offer's credentials by `credentialId` and instance,
    their answers and bound entries with the source and rulebook of each, its additions and
    display (A4); and the consent view with cards, claim rows, proof statement rows, additions,
    transactions and whether an offer needs the wallet's display (A9). A nym_auth request must be signed, trusted and encrypted, and its
    `verifier_id` comes from the authenticated certificate (N2).
  - One Credential Query refused with `invalid_request` refuses the whole request
    (`Answered::invalid_request`): a malformed `aki` value (`QueryRefusal::Authorities`), and a
    `zkp_req` query that breaks a request rule, the catalogue or the nym_auth policy. A query
    excludes a credential of its format and type, with its `Exclusion`, when the authorities
    refuse its issuer, its claims path processing gives an error, or it answers no option of a
    `zkp_req` query. A request without an offer gives its `Failure`: the refused query and why,
    the credentials the first query without candidates excludes and why (`excluded`), or no
    combination.
  - Phase 2 parses the selection against the plan made again, with the non-empty subset of each
    `multiple` member by `credentialId`, kept in the member's order. A selection that leaves out
    the credential an entry binds to is refused, and phase 2 binds the entries to the
    credentials the view named. `Planned::picked` makes the selection from the credential picker
    entries the user picked, each naming its offer, query and `credentialId` (K3). Phase 2 gives
    a `Sign` effect per signing input, verifies each signature under the instance's holder key
    (A5), and gives one `vp_token` (A8), its submission for the request's Response Mode and the
    presentation record. It proves `zkp_req` in-process through a `NymAuthProver`. A decline,
    and a background fulfilment of an offer that needs the wallet's display, give
    `access_denied`.
  - Positions and identifiers are their own types (`QueryIndex`, `CandidateIndex`, `SetIndex`,
    `OfferIndex`, `AdditionIndex`, `EntryPosition`, `PlanDigest`, `SignId`, and DCQL's
    `QueryId`), and so are A9's facts. The plan fetches nothing: the host gives it every input
    beforehand. Without the default feature `wallet` it holds the
    matching the picker runs, over `MatchCredential`, links no chain validation or response
    crypto, and builds with Rust 1.82: `Asked::of` takes an `UnverifiedRequest` or a
    `VerifiedRequest` (`MatchRequest`), `Transactions` selects transaction data over a
    `TransactionSource` and gives the offers or why there are none (`NoOffer`), and `Pick` is
    what a picker entry carries (K3). The feature `test-fixtures` holds the wallet, verifier,
    host and PaSO fixtures (`testing`).
- The `proving/` workspace: `siros-zkp-backend-longfellow` and `siros-zkp-backend-vega`
  implement the prover and verifier of each system over zk-cred-longfellow and zk-cred-vega,
  and check the circuit artifact the host fetched against its pin. CI runs real proofs of both
  systems. The matcher compiles no prover.
- FFI module `zkp_req`: `zkp_req_session`, `zkp_req_jwk_thumbprint`, `zkp_req_vp_token_json`,
  `zkp_req_vp_token_cbor`, and `zkp_req_verify` with a host-implemented `FfiProofVerifier`,
  whose `FfiProofCheck::Internal` reports a verifier that failed on its own inputs.
  `zkp_req_session` refuses, as `invalid_request`, a `client_id` that is no supported Client
  Identifier (its `ClientIdError` code) and a `nonce` outside the ASCII URL-safe characters
  (`nonce_malformed`), for both `verifier_id` forms; an absent or non-string `nonce` is
  `nonce_missing`. `zkp_req_verify` refuses a trust anchor that does not parse, a clock outside
  the years 0000 to 9999 and a negative tolerance as host errors (`now_out_of_range`,
  `tolerance_out_of_range`), and `zkp_req_vp_token_json` and `zkp_req_vp_token_cbor` refuse a
  query id outside §6.1. No FFI function produces a nym_auth proof.
- `siros-zkp-req-wasm` (in `proving/`), the browser module with both provers on one thread:
  `ZkpProvers` loads the artifacts and names the loaded systems, and `vpTokenJson` writes the
  `vp_token`. CI lints and builds it for `wasm32-unknown-unknown` and checks its imports. No
  browser export produces a nym_auth proof.
- Vectors: 49 protocol request vectors (`crates/siros-zkp-req/tests/vectors/request`), 72
  catalogue request vectors and 149 presentation vectors
  (`crates/siros-zkp-req-nym-auth/tests/vectors/`, the latter from
  `scripts/gen_zkp_req_presentation_vectors.py`), the `proof_time` vectors, the session and
  pseudonym vectors of zk-cred-vega, and `readdit.json`, the values of readdit `1cf3f26` for a
  differential test. Each changed expectation carries a `v0_4` note.
- Docs: `docs/zkp_req_core.md` (crates, flow, prover interface, API); `docs/zkp_req_request.md`
  and `docs/zkp_req_response.md` follow the draft; `docs/ecosystem.svg`, the README's overview
  of the layers, written by `scripts/gen_ecosystem_svg.py`.
- `scripts/vectors_digest.sh --digest` gives the vector set digest stated under Changed. The
  capability vectors (`circuit_capabilities/match.json`) are unchanged.
- `siros-registration`, the registration the wallet writes for the picker (K1, TR5), format
  version 2 in CBOR. Per credential it holds the entry reference, format and type, holder-key
  presence, the typed claim tree without nym_auth's undisclosable attributes, the card and the
  claim labels in the wallet's language, whether the wallet presents it without its UI, the
  TR5 facts, the card's title, issuer line and icon, and for each transaction data type the
  projected definition that serves it or why none does; each definition and icon is stored
  once. It also holds the system ids the wallet proves, the time of registration, the
  diagnostics flag and the wallet's default icon. `Registration::read`
  refuses a format `Version` other than `Version::CURRENT` (2) and every unexpected member, with a `RegistrationError` or the
  credential's `CredentialFault`. The writer (`write`, feature `wallet`) takes the parsed
  credentials, the presentation records, the display cache and language, the held transaction
  metadata and the configuration, the trust store, the systems, the credentials presented
  without the wallet's UI, the card fallbacks, the icons, the default icon and the time. An
  icon is a `RasterIcon`: a PNG or JPEG of 64 to 256 pixels in each direction, read from its
  header (`IconFault` otherwise). The host rasterises an SVG and resizes an image before it
  passes it; a credential without an icon of its own gets the default icon. `Unverified` is the picker's transaction
  data source. It builds with Rust 1.82.
- `scripts/gen_unicode_tables.py` writes the refused-character ranges of siros-display and the
  grapheme break runs of siros-transaction-data from their oracles' tables.
- siros-registration's example `sample_registration` writes the registration of a sample
  wallet; `scripts/run_matcher.mjs` runs `matcher.wasm` over it.
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
