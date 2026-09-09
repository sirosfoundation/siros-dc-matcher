# Changelog

`siros-dcql` is published to [crates.io](https://crates.io/crates/siros-dcql)
and versioned independently of the matcher repository it lives in. This file
records changes to *this crate's* public API.

Pre-1.0, a breaking change bumps the minor version, per
[Cargo's interpretation](https://doc.rust-lang.org/cargo/reference/semver.html)
of [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries for 0.1.0 and 0.2.0 are reconstructed from git history, which predates
this file.

## Unreleased

Releasing as **0.3.0**: the changes below are breaking, which pre-1.0 means a
minor bump.

### Added

- `CredentialSetQuery::purpose` (§6.2) — why the verifier wants a combination,
  as a `Value`, because the spec permits a string, an integer or an object.
- `Combination::purposes`, carrying the reasons of the credential sets a
  combination satisfies. Held per combination rather than only on the query,
  because a request with several sets offers several combinations and the
  reason shown beside one belongs to *its* set.
- `DcqlQuery::validate`, and `QueryError` describing why a query is unusable.
- `Credential::has_cryptographic_holder_binding`, and `QueryMatch::multiple`.

### Changed

- **Breaking.** `DcqlQuery::from_json` now returns `Result<Self, QueryError>`
  rather than `Result<Self, serde_json::Error>`, and validates identifiers on
  the way through. Validation is on the parse path rather than beside it so a
  caller cannot hold a query whose ids are ambiguous. `QueryError::Json` wraps
  what the old signature returned, and `QueryError` implements `Display` and
  `std::error::Error`, so a caller that only formatted the error needs no
  change.
- **Breaking.** `Combination` and `QueryMatch` each gained a field, so neither
  can be constructed with a struct literal from outside the crate.
- **Breaking.** `Credential` gained a required method,
  `has_cryptographic_holder_binding`, deliberately without a default. A blanket
  `true` would let an implementor who never considered the question assert a
  security property on their credentials' behalf, and the failure mode is a
  verifier being handed exactly what it said it would not accept.

### Fixed

- `require_cryptographic_holder_binding` (§6.1) is enforced. It was parsed and
  never read, so a verifier that required holder binding — which is the
  *default*, so also every verifier that said nothing — was offered unbound
  credentials regardless. Checked before format and claims, because an unbound
  credential is disqualified rather than a weaker match.
- `multiple` (§6.1) is evaluated. A query that sets it is now answered by every
  matching credential at once, rather than the flag being parsed and ignored.
  This is the reading under which it does anything: "multiple Credentials can
  be returned for this Credential Query". It also collapses the combination
  count where enumerating each credential as its own alternative would multiply
  it. `multiple: false` — the default — is unchanged and still yields at most
  one credential per query, as §6.4 requires.
- Duplicate identifiers are rejected instead of resolving to whichever came
  first. §6.1 requires a credential query `id` to be unique across the query
  and §6.3 requires a claims `id` to be unique within its array; without the
  check, a reference from `credential_sets` or `claim_sets` to a duplicated id
  named two different things and answered one, silently dropping the other. An
  empty credential query `id` is rejected for the same reason.

  The character restrictions §6.1 and §6.3 also place on an `id` are
  deliberately *not* enforced: they carry no meaning for matching, and failing
  a request over a dot in an identifier would reject a request that is
  perfectly well understood.

## 0.2.0 — 2026-08-30

### Added

- `QueryResult::combinations(limit)`, enumerating the ways a wallet can satisfy
  a request as sets of credentials presented *together* — what a picker offers
  as one selectable option.
- `Combination` and `Combinations`. The combination count is a product of the
  per-query candidate counts, so it is bounded by `limit` and computed by index
  arithmetic rather than by building the full product and discarding most of
  it. What is not built is reported in `Combinations::dropped` rather than
  silently omitted.
- `QueryResult::credential_sets`, so combinations can be enumerated from a
  result without also passing the query it came from.

## 0.1.0 — 2026-08-30

First release.

### Added

- The DCQL query model (OpenID4VP 1.0 §6): `DcqlQuery`, `CredentialQuery`,
  `ClaimsQuery`, `CredentialSetQuery`, faithful to the wire format, ignoring
  unknown properties as §6 instructs.
- Claims path pointers (§7): `PathComponent` and resolution against a
  credential, iteratively, so path depth cannot exhaust the stack.
- `execute`, applying §6.4 selection: a credential that cannot deliver every
  requested claim is not a match, and an absent `credential_sets` means every
  query must be satisfied rather than none.
- The `Credential` and `Policy` traits. `Policy` exists because §6.1 defines
  `meta` per credential format, so a generic engine cannot interpret it;
  `ExactFormat` covers the standalone case.
- `select_claims`, honouring `claims`, `claim_sets` and `values` exactly,
  including the type-strict comparison §6.3 requires.
