# `zkp_req` request shape and unsatisfiable requests

The request side of `docs/zkp_req_response.md`, following the `nym_auth`
rulebook v0.4 ("DCQL profile and presentation syntax", "Function catalogue").
Code: `crates/siros-dc-matcher-core/src/zkp_req.rs`. Vectors, in
`crates/siros-dc-matcher-core/tests/vectors/`: `zkp_req/` (structure) and
`zkp_req_unsat/` (unsatisfiable requests).

```json
{ "id": "nym_attestation", "format": "zkp_req",
  "meta": { "source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1" },
  "_req": [
    { "fn_id": "pseudonym", "return": "nym",
      "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256" } },
    { "fn_id": "age_check", "return": "age-range-123",
      "params": { "ge": "2008-10-10", "le": "2013-10-09" } } ] }
```

The verifier's constraints are `client_metadata.vp_formats_supported.zkp_req`
with `proof_system_values` and `system_id_values` (both OPTIONAL non-empty
arrays). Over `mso_mdoc` the attestation is the stored ISO/IEC 18013-5 mdoc.

## Structure (`plan`)

`plan` refuses, with a stable code: a query that is not a JSON object
(`query_not_parseable`); a missing, non-array or empty `_req`
(`req_missing_or_empty`); an item without `fn_id` or `return`
(`item_missing_function_id`, `item_missing_handle`); a repeated handle
(`duplicate_handle`); a parameter of the wrong JSON type (`param_wrong_type`:
`config`, `prf`, `verifier_context` strings, `ver` an integer, `ge` and `le`
strings) or a date that is not an RFC 3339 `full-date`
(`param_invalid_full_date`); `claims` in any form (`claims_present`),
`claim_sets` (`claim_sets_present`) or `_req_sets` (`req_sets_present`); a
`meta` that is not an object, has no string `source_format`, or has a type
value of the wrong type (`invalid_meta`); a `client_metadata` of the wrong
shape (`invalid_client_metadata`).

## Unsatisfiable requests (`unsatisfiable`)

The rulebook calls these requests unsatisfiable; the evaluator never offers
one (the first rule broken is the code):

| code | rule |
|---|---|
| `source_format_unsupported` | `source_format` is not `mso_mdoc` or `bbs_cd` (`dc+sd-jwt` is reserved) |
| `meta_type_value_invalid` | `meta` lacks exactly the type value of its source format (`doctype_value` for `mso_mdoc`, `schema_id_value` for `bbs_cd`), or carries `vct_values` |
| `holder_binding_waived` | `require_cryptographic_holder_binding` is `false` |
| `function_unknown` | a `fn_id` the rulebook does not define (`pseudonym`, `age_check`) |
| `pseudonym_repeated`, `age_check_repeated` | more than one item of the function |
| `pseudonym_config_missing`, `pseudonym_config_unknown` | `config` absent, or not one of the four defined configurations |
| `pseudonym_ver_missing`, `pseudonym_ver_unsupported` | `ver` absent, or not 1 |
| `pseudonym_prf_missing`, `pseudonym_prf_unsupported` | `prf` absent, or not defined for the source format and configuration: `sha-256` for `mso_mdoc`; `hashdh-bls12381g1` for `bbs_cd` with `known-offender-matching-ssc` only |
| `verifier_context_invalid` | absent for `account-recovery-ssc`, present for any other configuration, or not 1 to 64 UTF-8 **bytes** |
| `age_check_no_bound`, `age_check_inverted`, `age_check_span_too_short` | neither `ge` nor `le`; `le` before `ge`; `le - ge + 1` below 365 days |

A request that passes is not thereby served. **Which configurations and
parameters a system supports is its registry entry's say** (the circuit's
`capabilities`: a function lists its parameters, and a parameter or value not
listed is refused). A configuration the entry does not list, such as
`known-offender-matching-psc` for a circuit that proves only
`known-offender-matching-ssc`, is not served: the matcher never claims support
beyond the entry. A registry entry for a `pseudonym` circuit therefore lists
`config`, `ver` and `prf`.

## `source_format` and stored attestations

The attestation a proof is made over must be of the request's `source_format`.
The default profile stores `mso_mdoc` only, so a `bbs_cd` request is not
offered until a wallet stores a `bbs_cd` attestation and the profile maps
`zkp_req` onto it; the request plans and nothing else breaks.

## Non-disclosure

`ssc`, `psc`, `secret_seed` and `birth_date` of a nym_auth attestation
(`eu.europa.ec.eudi.nym_auth.1`, `eu.europa.ec.eudi.nym_auth.bbs.1`) are never
disclosed. A request through any format other than `zkp_req` that names one of
them, uses a wildcard path, or has no `claims` at all (which asks for the whole
attestation) does not match that attestation. `birth_date` of any other
credential is an ordinary claim.
