# `zkp_req` response shape

Normative description of what a wallet returns for a `zkp_req` credential
query, and what a verifier-side shape check accepts. It follows the `nym_auth`
rulebook v0.4 ("Presentation encoding"); the rulebook text wins wherever the two
differ. It is the counterpart of the request side (`_req` items with `return`
handles; see `docs/zkp_req_request.md` and the planner in
`crates/siros-dc-matcher-core/src/zkp_req.rs`). Conformance vectors:
`crates/siros-dc-matcher-core/tests/vectors/zkp_req_response/`. Reference check:
`zkp_req_response::validate_response`.

This checks **shape and binding to the request**. It does not verify the proof
or any certificate.

## Shape

The response rides in `vp_token`, keyed by the DCQL credential query `id`. The
value is an **array** of presentations, one element per matched credential.
Each element is a JSON string: the base64url encoding (RFC 4648 section 5,
without padding) of the CBOR encoding of a `ZkpPresentation`.

```json
{ "nym_attestation": ["<base64url(CBOR(ZkpPresentation))>"] }
```

```cddl
ZkpPresentation = {
  "system_id"      => tstr,         ; approved system used: a circuit or scheme identifier
  "proof"          => bstr,
  "issuer_key_set" => [+ bstr],     ; mso_mdoc: DER Document Signer certificates
  ? "proof_time"   => tdate,        ; tag 0
  "results"        => { + tstr => ResultValue }
}
ResultValue    = PseudonymValue / PredicateValue
PseudonymValue = bstr             ; length set by the pseudonym's `prf`
PredicateValue = true
```

There is **one proof per credential**, not per `_req` item. Handles key the
`results`, not proofs. The presentation carries no proof system and no
`circuit_id`: the system is named by `system_id` alone, and the verifier's
registry maps it to a proof system.

## Rules

A presentation that breaks any rule is refused (the whole response is refused;
there is no partial acceptance). Reason codes are stable identifiers.

1. **Envelope.** `vp_token` is a JSON object with an entry for the query `id`
   (`response_not_parseable`, `duplicate_member` for a repeated member name,
   `query_id_missing`); that entry is a non-empty array
   (`presentations_not_array`, `presentations_empty`). Entries for other query
   ids are ignored. More than one element is allowed only when the credential
   query sets `multiple: true` (DCQL: omitted means false):
   `presentations_multiple_not_allowed`. Every element is checked against the
   same request.
2. **Element encoding.** Each element is a JSON string (`presentation_not_string`)
   holding unpadded base64url: alphabet `A-Z a-z 0-9 - _`, no `=`, no `+` `/`,
   no whitespace, a canonical final character (`presentation_not_base64url`).
3. **Strict CBOR.** The decoded bytes are exactly one CBOR item. Refused:
   truncation, a reserved encoding, text that is not UTF-8, nesting deeper than
   16 levels (`cbor_malformed`); an indefinite-length byte string, text string,
   array or map at any level (`cbor_indefinite_length`); bytes after the item
   (`cbor_trailing_bytes`); a map that repeats a key at any level
   (`cbor_duplicate_key`; keys are compared structurally, so a repeated key is
   refused even when the values are identical). Integers and lengths in
   non-shortest form are accepted: the reader is not a canonicality check.
4. **Members.** The item is a map (`presentation_not_map`) whose keys are all
   text strings (`presentation_key_not_text`). Members are exactly
   `system_id`, `proof`, `issuer_key_set`, `proof_time`, `results`; another
   name is refused (`presentation_unknown_member`), which includes `error`,
   `error_description` and the pre-v0.4 `proof_system`, `circuit_id`, `x5chain`.
   `system_id`, `proof`, `issuer_key_set` and `results` are REQUIRED
   (`presentation_member_missing`). Types: `system_id` tstr, `proof` bstr,
   `issuer_key_set` array, `results` map (`presentation_member_wrong_type`).
   CBOR `null` is a value of the wrong type, never "absent".
   Member order is irrelevant.
5. **Binding to the offer.** `system_id` MUST be in the request's
   `client_metadata.vp_formats_supported.zkp_req.system_id_values`
   (`system_id_not_offered`). If the request stated no list, nothing was
   offered and the response is refused (fail closed). `proof_system_values` is
   not checkable here: the presentation does not carry a proof system.
6. **Proof.** `proof` is non-empty (`proof_empty`). It is opaque here.
7. **Issuer key set.** A non-empty array (`issuer_key_set_empty`) of at most
   **8** elements (`issuer_key_set_too_many`), each a non-empty
   (`issuer_key_empty`) byte string (`issuer_key_not_bytes`) of at most **4096**
   bytes (`issuer_key_too_large`). Elements are checked in array order. For
   `mso_mdoc` each is a DER Document Signer certificate, leaf first; the
   matcher checks **encoding and limits only** and does not parse X.509. The
   verifier validates every element against its trust anchors (go-trust) and
   takes the issuer key from the validated certificate; it never looks up
   issuer keys itself.
8. **`proof_time`.** When the request's `meta.source_format` is `mso_mdoc` it is
   REQUIRED (`proof_time_missing`): every approved circuit checks the MSO
   validity period. For other source formats (`bbs_cd`) it is optional. When
   present it is a tag-0 text string (`proof_time_not_tdate`) in the **exact
   20-byte form** `YYYY-MM-DDThh:mm:ssZ` (`proof_time_form`): second precision,
   no fractional seconds, `T` and `Z` upper case, no offset, a real UTC
   instant (no month 13, no 30 February, hour at most 23, second at most 59).
   It is the circuit's public input, byte-identical between prover and
   verifier. See "proof_time" below.
9. **Handles.** The keys of `results` are text strings (`result_key_not_text`)
   and are exactly the `return` handles of the request's `_req` items: an extra
   handle (`result_handle_unexpected`) and a missing handle
   (`result_handle_missing`) are refused. Key order is irrelevant. A repeated
   key is `cbor_duplicate_key` (rule 3).
10. **Result values**, by function, in request order:
    - `pseudonym` -> a byte string (`result_wrong_type`) whose length is set
      by the item's `prf`: **32** for `sha-256`, **48** for
      `hashdh-bls12381g1` (`pseudonym_wrong_length`). An item with no known
      `prf` has no length to demand (`pseudonym_prf_unknown`).
    - `age_check` -> `true`. `false` is never valid (`result_not_satisfied`):
      an unsatisfiable predicate is a decline, not a result. Anything else
      (`1`, `"true"`, `null`, the pre-v0.4 `{"satisfied": true}`) is
      `result_wrong_type`.
    - A function the validator has no result shape for is refused
      (`result_function_unknown`).

## `proof_time`

The prover supplies `proof_time` (the rulebook's decision; there is no
verifier-chosen time and no `iat` binding). The verifier assembles the circuit's
public input from the value in the presentation and MUST reject a presentation
whose `proof_time` deviates from its own clock by more than its tolerance.

`proof_time::check_tolerance(proof_time, now, skew, max_age)` is the helper:
it accepts `now - max_age <= proof_time <= now + skew`, both inclusive, and
refuses anything that is not the exact 20-byte form. The recommended defaults
are **60 s** of skew into the future and **600 s** of age, exposed as
`RECOMMENDED_SKEW_SECS` and `RECOMMENDED_MAX_AGE_SECS`. They are
recommendations, not protocol constants: the tolerance is the verifier's.
Vectors: `crates/siros-dc-matcher-core/tests/vectors/zkp_req_response`
(`ok_proof_time_*`, `err_proof_time_*`) for the form;
`crates/siros-dc-matcher-core/tests/proof_time.rs` for the tolerance.

`proof_time::render(secs)` and `proof_time::parse(text)` convert between epoch
seconds and the 20-byte form (0 to 253402300799, i.e. 1970-01-01T00:00:00Z to
9999-12-31T23:59:59Z).

## Verifier identity (not checked here)

The matcher derives no pseudonym and so has no vector that depends on how
`verifier_input` is formed. For the record (rulebook v0.4): `verifier_input` is
`SHA-256(verifier_id)` with `verifier_id` the **prefixed** string: for
`x509_san_dns` the Client Identifier including its prefix
(`x509_san_dns:verifier.example`), for `semantic` `semantic_id:` followed by the
semantic identifier (taken from the registration certificate when present,
otherwise the access certificate). The bare DNS name is not a `verifier_id`.

## Order of checks

The first failure in this order is the one reported: envelope (rule 1), then
per presentation in array order: element encoding (2), CBOR (3), members (4:
not a map, key types, unknown members, presence, types), offer binding (5),
proof (6), issuer key set (7: count, then each element in order), `proof_time`
(8), handles (9: unexpected, then missing, all before any value), then result
values per `_req` item in request order (10). Vectors `err_order_*` pin each
adjacent pair.

## Decisions worth knowing

- **Strict on unknown members** in the presentation, matching the request
  side's strictness. New members or functions need a new vector and a
  validator change; they do not slip through. `proof_time` is optional in the
  CDDL but required for `mso_mdoc` by rule 8, the strictest reading of "present
  when the system checks validity".
- **Unknown request functions refuse the response** (`result_function_unknown`):
  a response to a function with no result shape cannot be validated.
- **Empty array refused.** A response with zero presentations is a decline in
  disguise. A decline is an OpenID4VP error response, never a presentation.
- **Duplicates are judged on the bytes.** CBOR maps are read into ordered
  pairs, never a hash map, so a repeated key cannot be silently collapsed.
  The `vp_token` JSON object is read the same way (`duplicate_member`,
  vectors use `vp_token_text`).
- **`bbs_cd` is held.** Its presentations validate by the same rules (a 48-byte
  pseudonym, `proof_time` optional); vectors `ok_bbs_cd_*` pin that. Nothing
  more is claimed for it: no key-set size or key length beyond the general
  limits.
