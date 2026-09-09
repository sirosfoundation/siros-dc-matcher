# Changelog

`siros-dcql` is published to [crates.io](https://crates.io/crates/siros-dcql)
and versioned independently of the matcher repository it lives in. This file
records changes to *this crate's* public API.

Pre-1.0, a breaking change bumps the minor version, per
[Cargo's interpretation](https://doc.rust-lang.org/cargo/reference/semver.html)
of [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries for 0.1.0 and 0.2.0 are reconstructed from git history, which predates
this file.

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
