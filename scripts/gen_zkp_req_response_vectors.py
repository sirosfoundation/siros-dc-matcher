#!/usr/bin/env python3
"""Regenerates crates/siros-dc-matcher-core/tests/vectors/zkp_req_response/.

Deterministic: running it twice yields byte-identical files. The CBOR is
encoded here by hand (shortest form, definite lengths) so the vectors do not
depend on a CBOR library. Run from anywhere:

    python3 scripts/gen_zkp_req_response_vectors.py
"""
import base64
import json
import os

OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "crates", "siros-dc-matcher-core", "tests", "vectors", "zkp_req_response",
)

# ---- CBOR (RFC 8949), minimal encoder ------------------------------------
def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 1 << 8: return bytes([major << 5 | 24, n])
    if n < 1 << 16: return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 1 << 32: return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    return bytes([major << 5 | 27]) + n.to_bytes(8, "big")
def uint(n): return head(0, n)
def bstr(b): return head(2, len(b)) + b
def tstr(s): return head(3, len(s.encode())) + s.encode()
def arr(items): return head(4, len(items)) + b"".join(items)
def mp(pairs): return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
def tag(n, item): return head(6, n) + item
TRUE, FALSE, NULL = b"\xf5", b"\xf4", b"\xf6"
def tdate(s): return tag(0, tstr(s))

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

# ---- shared request ------------------------------------------------------
SYS = "urn:circuits:longfellow:nym_auth:v1"
BBS_SYS = "urn:mms:bbs-cd:nym_auth:v1"
PT = "2026-10-20T12:00:00Z"
PROOF = bytes(range(32))
KEY = b"\x30\x82\x01\x0a" + bytes(range(64))   # stands for a DER certificate
NYM = bytes(range(32))

def query(items=None, meta=None, **extra):
    q = {
        "id": "nym_attestation",
        "format": "zkp_req",
        "meta": meta or {"source_format": "mso_mdoc", "doctype_value": "eu.europa.ec.eudi.nym_auth.1"},
        "_req": items or [PSEUDONYM, AGE],
    }
    q.update(extra)
    return q
PSEUDONYM = {"fn_id": "pseudonym", "return": "nym",
             "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "sha-256"}}
AGE = {"fn_id": "age_check", "return": "age-range-123",
       "params": {"ge": "2008-10-10", "le": "2013-10-09"}}
def cm(systems=(SYS,)):
    return {"vp_formats_supported": {"zkp_req": {
        "proof_system_values": ["longfellow-libzk-v1"], "system_id_values": list(systems)}}}
BBS_META = {"source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1"}
BBS_PSEUDONYM = {"fn_id": "pseudonym", "return": "nym",
                 "params": {"config": "known-offender-matching-ssc", "ver": 1, "prf": "hashdh-bls12381g1"}}

def results(nym=NYM, age=TRUE, order=("nym", "age-range-123"), extra=(), drop=(), nym_raw=None):
    vals = {"nym": bstr(nym) if nym_raw is None else nym_raw, "age-range-123": age}
    pairs = [(tstr(k), vals[k]) for k in order if k in vals and k not in drop]
    return mp(pairs + list(extra))

def pres(system_id=None, proof=None, keys=None, proof_time="default", res=None,
         omit=(), extra=(), order=None, raw=None):
    """Encode a ZkpPresentation. `raw` replaces a member's encoding."""
    m = {
        "system_id": tstr(SYS) if system_id is None else system_id,
        "proof": bstr(PROOF) if proof is None else proof,
        "issuer_key_set": arr([bstr(KEY)]) if keys is None else keys,
        "results": results() if res is None else res,
    }
    if proof_time == "default": m["proof_time"] = tdate(PT)
    elif proof_time is not None: m["proof_time"] = proof_time
    for k, v in (raw or {}).items(): m[k] = v
    names = order or ["system_id", "proof", "issuer_key_set", "proof_time", "results"]
    pairs = [(tstr(n), m[n]) for n in names if n in m and n not in omit]
    return mp(pairs + [(tstr(k), v) for k, v in extra])

def vp(*presentations, key="nym_attestation", **others):
    t = {key: [b64u(p) if isinstance(p, bytes) else p for p in presentations]}
    t.update(others)
    return t

VECTORS = {}
def add(name, desc, vp_token=None, q=None, client=None, text=None):
    v = {"description": desc, "query": q or query(), "client_metadata": cm() if client is None else client}
    if text is not None: v["vp_token_text"] = text
    else: v["vp_token"] = vp_token
    v["expect"] = {"valid": True} if name.startswith("ok_") else None
    VECTORS[name] = v
def ok(name, desc, *a, **k): add("ok_" + name, desc, *a, **k)
def err(name, code, desc, *a, **k):
    add("err_" + name, desc, *a, **k); VECTORS["err_" + name]["expect"] = {"error": code}

P = pres
# ---- valid ---------------------------------------------------------------
ok("normative_both", "Rulebook example: a pseudonym (32 bytes) and an age predicate, proof_time in the exact 20-byte form.", vp(P()))
ok("pseudonym_only", "Only a pseudonym requested.", vp(P(res=results(drop=("age-range-123",)))), q=query(items=[PSEUDONYM]))
ok("age_check_only", "Only an age predicate requested.", vp(P(res=results(drop=("nym",)))), q=query(items=[AGE]))
ok("results_order_irrelevant", "Result keys in any order.", vp(P(res=results(order=("age-range-123", "nym")))))
ok("member_order_irrelevant", "Presentation members in any order (CBOR map order carries no meaning).",
   vp(P(order=["results", "proof_time", "issuer_key_set", "proof", "system_id"])))
ok("two_presentations", "multiple: true allows more than one presentation; each is checked.", vp(P(), P()), q=query(multiple=True))
ok("other_query_ids_ignored", "Entries for other credential queries are not looked at.", vp(P(), other=["garbage"]))
ok("issuer_key_set_single", "One certificate (the usual set for a system whose circuit takes one issuer key).", vp(P()))
ok("issuer_key_set_limits", "Eight certificates, the last of exactly 4096 bytes: both limits inclusive.",
   vp(P(keys=arr([bstr(KEY)] * 7 + [bstr(b"\x30" * 4096)]))))
ok("proof_time_epoch", "proof_time at the Unix epoch.", vp(P(proof_time=tdate("1970-01-01T00:00:00Z"))))
ok("proof_time_leap_day", "proof_time on a leap day, last second.", vp(P(proof_time=tdate("2024-02-29T23:59:59Z"))))
ok("proof_time_year_end", "proof_time across a year boundary.", vp(P(proof_time=tdate("2026-12-31T23:59:59Z"))))
ok("proof_time_max", "Largest renderable proof_time.", vp(P(proof_time=tdate("9999-12-31T23:59:59Z"))))
ok("proof_time_century_non_leap", "2100 is not a leap year: 2100-02-28 is valid.", vp(P(proof_time=tdate("2100-02-28T00:00:00Z"))))
ok("bbs_cd_no_proof_time", "bbs_cd (held): a 48-byte pseudonym (prf hashdh-bls12381g1) and no proof_time (the encoding carries no validity period).",
   vp(P(system_id=tstr(BBS_SYS), proof_time=None, res=results(nym=bytes(48), drop=("age-range-123",)))),
   q=query(items=[BBS_PSEUDONYM], meta=BBS_META), client=cm((BBS_SYS,)))
ok("bbs_cd_with_proof_time", "bbs_cd: proof_time is optional there; when present it is checked like any other.",
   vp(P(system_id=tstr(BBS_SYS), res=results(nym=bytes(48), drop=("age-range-123",)))),
   q=query(items=[BBS_PSEUDONYM], meta=BBS_META), client=cm((BBS_SYS,)))

# ---- envelope --------------------------------------------------------------
err("not_json", "response_not_parseable", "vp_token is not JSON.", text="{not json")
err("not_object", "response_not_parseable", "vp_token is a JSON array.", text="[]")
err("null_vp_token", "response_not_parseable", "vp_token is JSON null.", text="null")
err("duplicate_member", "duplicate_member", "The vp_token object repeats a member name (raw text: a parsed object cannot hold it).",
    text='{"nym_attestation":["AA"],"nym_attestation":["AA"]}')
err("query_id_missing", "query_id_missing", "No entry for the query id.", vp(P(), key="other"))
err("presentations_not_array", "presentations_not_array", "The entry is an object.", {"nym_attestation": {}})
err("null_query_entry", "presentations_not_array", "The entry is null: a type error, not absence.", {"nym_attestation": None})
err("presentations_empty", "presentations_empty", "An empty array is a decline in disguise.", {"nym_attestation": []})
err("multiple_not_allowed", "presentations_multiple_not_allowed", "Two presentations without multiple: true.", vp(P(), P()))
err("multiple_false", "presentations_multiple_not_allowed", "Two presentations with multiple: false.", vp(P(), P()), q=query(multiple=False))
err("second_presentation_bad", "result_handle_missing", "Every presentation is checked, not only the first.",
    vp(P(), P(res=results(drop=("age-range-123",)))), q=query(multiple=True))
err("presentation_not_string", "presentation_not_string", "An element is a number.", {"nym_attestation": [1]})
err("presentation_object", "presentation_not_string", "An element is a JSON object (the pre-v0.4 JSON presentation).",
    {"nym_attestation": [{"circuit_id": SYS}]})
err("null_presentation", "presentation_not_string", "An element is JSON null.", {"nym_attestation": [None]})
good = b64u(P())
err("presentation_padded", "presentation_not_base64url", "Padding is not allowed.", {"nym_attestation": [good + "=" * (-len(good) % 4) if len(good) % 4 else good + "="]})
err("presentation_standard_alphabet", "presentation_not_base64url", "Standard alphabet: '+' or '/' instead of '-' or '_'.",
    {"nym_attestation": [good[:10] + "+" + good[11:]]})
err("presentation_whitespace", "presentation_not_base64url", "Embedded whitespace.", {"nym_attestation": [good[:8] + " " + good[8:]]})
def noncanonical():
    for extra in range(0, 4):
        s = b64u(P(proof=bstr(PROOF + bytes(extra))))
        if len(s) % 4 in (2, 3):
            alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            i = alpha.index(s[-1])
            return s[:-1] + alpha[i | 1]
err("presentation_noncanonical_final_char", "presentation_not_base64url", "Non-zero trailing bits in the last character.", {"nym_attestation": [noncanonical()]})

# ---- CBOR -----------------------------------------------------------------
def raw_err(name, code, desc, data):
    err(name, code, desc, {"nym_attestation": [b64u(data)]})
whole = P()
raw_err("cbor_empty", "cbor_malformed", "Zero bytes.", b"")
raw_err("cbor_truncated", "cbor_malformed", "The map is cut off.", whole[:-3])
raw_err("cbor_reserved_info", "cbor_malformed", "Additional information 28 is reserved.", b"\x1c")
raw_err("cbor_invalid_utf8", "cbor_malformed", "A text-string key that is not UTF-8.", head(5, 1) + head(3, 2) + b"\xff\xfe" + TRUE)
raw_err("cbor_impossible_length", "cbor_malformed", "An array claims 2^32 elements; refused without allocating.", b"\x9a\xff\xff\xff\xff")
raw_err("cbor_too_deep", "cbor_malformed", "Seventeen levels of nesting.", b"\x81" * 17 + b"\x00")
raw_err("cbor_break_outside", "cbor_malformed", "A stray break byte.", b"\xff")
raw_err("cbor_indefinite_map", "cbor_indefinite_length", "An indefinite-length map (0xbf ... 0xff).",
        b"\xbf" + b"".join(k + v for k, v in [(tstr("system_id"), tstr(SYS)), (tstr("proof"), bstr(PROOF)),
        (tstr("issuer_key_set"), arr([bstr(KEY)])), (tstr("proof_time"), tdate(PT)), (tstr("results"), results())]) + b"\xff")
raw_err("cbor_indefinite_array", "cbor_indefinite_length", "issuer_key_set as an indefinite-length array.",
        P(keys=b"\x9f" + bstr(KEY) + b"\xff"))
raw_err("cbor_indefinite_bstr", "cbor_indefinite_length", "proof as an indefinite-length byte string.",
        P(proof=b"\x5f" + bstr(PROOF[:16]) + bstr(PROOF[16:]) + b"\xff"))
raw_err("cbor_indefinite_tstr", "cbor_indefinite_length", "A result handle as an indefinite-length text string.",
        P(res=mp([(b"\x7f" + tstr("nym") + tstr("") + b"\xff", bstr(NYM)), (tstr("age-range-123"), TRUE)])))
raw_err("cbor_trailing_bytes", "cbor_trailing_bytes", "One extra byte after the map.", whole + b"\x00")
raw_err("cbor_two_items", "cbor_trailing_bytes", "Two concatenated presentations.", whole + whole)
raw_err("cbor_duplicate_member", "cbor_duplicate_key", "The presentation map repeats `proof`.",
        P(extra=[("proof", bstr(PROOF))]) if False else mp([(tstr("system_id"), tstr(SYS)), (tstr("proof"), bstr(PROOF)), (tstr("proof"), bstr(PROOF)),
        (tstr("issuer_key_set"), arr([bstr(KEY)])), (tstr("proof_time"), tdate(PT)), (tstr("results"), results())]))
raw_err("cbor_duplicate_handle", "cbor_duplicate_key", "results repeats a handle.",
        P(res=mp([(tstr("nym"), bstr(NYM)), (tstr("nym"), bstr(NYM)), (tstr("age-range-123"), TRUE)])))
raw_err("cbor_duplicate_key_same_value_different_form", "cbor_duplicate_key", "A repeated key is refused even when both values are identical.",
        P(res=mp([(tstr("age-range-123"), TRUE), (tstr("age-range-123"), TRUE), (tstr("nym"), bstr(NYM))])))

# ---- presentation shape -----------------------------------------------------
raw_err("presentation_array", "presentation_not_map", "The presentation is a CBOR array.", arr([tstr(SYS)]))
raw_err("presentation_text", "presentation_not_map", "The presentation is a text string.", tstr("x"))
raw_err("presentation_null", "presentation_not_map", "The presentation is CBOR null.", NULL)
raw_err("presentation_key_uint", "presentation_key_not_text", "A presentation key is an integer.", mp([(uint(1), tstr(SYS))]))
raw_err("presentation_key_bytes", "presentation_key_not_text", "A presentation key is a byte string.", mp([(bstr(b"system_id"), tstr(SYS))]))
for legacy in ("proof_system", "x5chain", "circuit_id", "error", "error_description", "extra"):
    err("unknown_member_" + legacy, "presentation_unknown_member",
        f"A member `{legacy}` outside the defined five" + (" (pre-v0.4 JSON member)." if legacy in ("proof_system", "x5chain", "circuit_id") else ("; an in-band error is no different from any other unknown member." if legacy.startswith("error") else ".")),
        vp(P(extra=[(legacy, tstr("x"))])))
for m in ("system_id", "proof", "issuer_key_set", "results"):
    err("member_missing_" + m, "presentation_member_missing", f"`{m}` absent.", vp(P(omit=(m,))))
err("wrong_type_system_id", "presentation_member_wrong_type", "system_id is a byte string.", vp(P(system_id=bstr(SYS.encode()))))
err("wrong_type_proof_text", "presentation_member_wrong_type", "proof is a text string.", vp(P(proof=tstr("proof"))))
err("wrong_type_issuer_key_set_map", "presentation_member_wrong_type", "issuer_key_set is a map.", vp(P(keys=mp([]))))
err("wrong_type_issuer_key_set_bstr", "presentation_member_wrong_type", "issuer_key_set is a single byte string, not an array.", vp(P(keys=bstr(KEY))))
err("wrong_type_results_array", "presentation_member_wrong_type", "results is an array.", vp(P(res=arr([]))))
err("null_system_id", "presentation_member_wrong_type", "system_id is CBOR null: wrong type, not absent.", vp(P(system_id=NULL)))
err("null_proof", "presentation_member_wrong_type", "proof is CBOR null.", vp(P(proof=NULL)))
err("null_issuer_key_set", "presentation_member_wrong_type", "issuer_key_set is CBOR null.", vp(P(keys=NULL)))
err("null_results", "presentation_member_wrong_type", "results is CBOR null.", vp(P(res=NULL)))

# ---- binding, proof, issuer key set ------------------------------------------
err("system_id_not_offered", "system_id_not_offered", "system_id is not in system_id_values.", vp(P(system_id=tstr("urn:circuits:other:v1"))))
err("system_id_no_offer_list", "system_id_not_offered", "The request stated no system_id_values: nothing was offered, fail closed.", vp(P()), client={})
err("system_id_empty_offer_list", "system_id_not_offered", "An empty system_id_values offers nothing.", vp(P()), client=cm(()))
err("proof_empty", "proof_empty", "proof is a zero-length byte string.", vp(P(proof=bstr(b""))))
err("issuer_key_set_empty", "issuer_key_set_empty", "issuer_key_set is an empty array.", vp(P(keys=arr([]))))
err("issuer_key_set_too_many", "issuer_key_set_too_many", "Nine certificates.", vp(P(keys=arr([bstr(KEY)] * 9))))
err("issuer_key_not_bytes", "issuer_key_not_bytes", "An element is a text string (a base64 certificate, as in the pre-v0.4 x5chain).", vp(P(keys=arr([tstr("MIIB")]))))
err("issuer_key_null", "issuer_key_not_bytes", "An element is CBOR null.", vp(P(keys=arr([NULL]))))
err("issuer_key_second_not_bytes", "issuer_key_not_bytes", "Elements are checked in order: the second is bad.", vp(P(keys=arr([bstr(KEY), uint(1)]))))
err("issuer_key_empty", "issuer_key_empty", "A zero-length element.", vp(P(keys=arr([bstr(b"")]))))
err("issuer_key_too_large", "issuer_key_too_large", "An element of 4097 bytes.", vp(P(keys=arr([bstr(b"\x30" * 4097)]))))

# ---- proof_time ----------------------------------------------------------------
err("proof_time_missing", "proof_time_missing", "mso_mdoc circuits check validity: proof_time is required.", vp(P(proof_time=None)))
err("proof_time_plain_text", "proof_time_not_tdate", "A text string without tag 0.", vp(P(proof_time=tstr(PT))))
err("proof_time_epoch_tag", "proof_time_not_tdate", "Tag 1 (epoch time) is not tdate.", vp(P(proof_time=tag(1, uint(1760961600)))))
err("proof_time_tag0_bytes", "proof_time_not_tdate", "Tag 0 around a byte string.", vp(P(proof_time=tag(0, bstr(PT.encode())))))
err("proof_time_plain_uint", "proof_time_not_tdate", "An integer.", vp(P(proof_time=uint(1760961600))))
err("proof_time_null", "proof_time_not_tdate", "proof_time is CBOR null: a type error, not absence.", vp(P(proof_time=NULL)))
for name, text, why in [
    ("fraction", "2026-10-20T12:00:00.000Z", "fractional seconds"),
    ("offset", "2026-10-20T12:00:00+00:00", "a numeric offset instead of Z"),
    ("lowercase_z", "2026-10-20T12:00:00z", "a lowercase z"),
    ("lowercase_t", "2026-10-20t12:00:00Z", "a lowercase t"),
    ("space", "2026-10-20 12:00:00Z", "a space instead of T"),
    ("no_seconds", "2026-10-20T12:00Z", "no seconds (RFC 3339 requires them; 17 bytes)"),
    ("date_only", "2026-10-20", "a date without a time"),
    ("short_year", "26-10-20T12:00:00Z", "a two-digit year"),
    ("month_13", "2026-13-20T12:00:00Z", "month 13"),
    ("not_leap_day", "2026-02-29T12:00:00Z", "29 February in a non-leap year"),
    ("century_not_leap", "2100-02-29T00:00:00Z", "29 February 2100 (not a leap year)"),
    ("hour_24", "2026-10-20T24:00:00Z", "hour 24"),
    ("second_60", "2026-10-20T23:59:60Z", "a leap second (the circuit input has none)"),
    ("trailing_space", "2026-10-20T12:00:00Z ", "a trailing space (21 bytes)"),
    ("empty", "", "an empty string"),
    ("non_ascii_digit", "2026-10-20T12:00:0٠Z", "a non-ASCII digit"),
]:
    err("proof_time_" + name, "proof_time_form", f"proof_time is a tdate but not the exact 20-byte form: {why}.", vp(P(proof_time=tdate(text))))

# ---- results ----------------------------------------------------------------------
err("result_key_not_text", "result_key_not_text", "A results key is an integer.", vp(P(res=mp([(uint(1), bstr(NYM)), (tstr("age-range-123"), TRUE)]))))
err("result_handle_unexpected", "result_handle_unexpected", "A handle the request did not return.", vp(P(res=results(extra=[(tstr("extra"), TRUE)]))))
err("result_handle_missing", "result_handle_missing", "A returned handle has no result.", vp(P(res=results(drop=("age-range-123",)))))
err("result_empty", "result_handle_missing", "results is an empty map (the rulebook requires at least one entry).", vp(P(res=mp([]))))
err("result_of_other_function", "result_handle_unexpected", "Result keyed by the function id instead of the handle.", vp(P(res=mp([(tstr("pseudonym"), bstr(NYM)), (tstr("age_check"), TRUE)]))))
err("result_function_unknown", "result_function_unknown", "The request has a function this validator has no result shape for.",
    vp(P(res=mp([(tstr("x"), TRUE)]))), q=query(items=[{"fn_id": "no-such-fn", "return": "x"}]))
err("pseudonym_text", "result_wrong_type", "A pseudonym as a hex text string.", vp(P(res=results(nym_raw=tstr(NYM.hex())))))
err("pseudonym_null", "result_wrong_type", "A pseudonym of CBOR null.", vp(P(res=results(nym_raw=NULL))))
err("pseudonym_true", "result_wrong_type", "A pseudonym of true.", vp(P(res=results(nym_raw=TRUE))))
err("predicate_uint", "result_wrong_type", "A predicate result of 1.", vp(P(res=results(age=uint(1)))))
err("predicate_text", "result_wrong_type", "A predicate result of the text \"true\".", vp(P(res=results(age=tstr("true")))))
err("predicate_null", "result_wrong_type", "A predicate result of CBOR null.", vp(P(res=results(age=NULL))))
err("predicate_object", "result_wrong_type", "The pre-v0.4 shape {\"satisfied\": true}.", vp(P(res=results(age=mp([(tstr("satisfied"), TRUE)])))))
err("predicate_false", "result_not_satisfied", "false is never a valid result: an unsatisfiable predicate is a decline.", vp(P(res=results(age=FALSE))))
for n in (0, 16, 31, 33, 48, 64):
    err(f"pseudonym_length_{n}", "pseudonym_wrong_length", f"A {n}-byte pseudonym where prf sha-256 sets 32.", vp(P(res=results(nym=bytes(n)))))
err("pseudonym_hashdh_wrong_length", "pseudonym_wrong_length", "prf hashdh-bls12381g1 sets 48 bytes; 32 is refused.",
    vp(P(system_id=tstr(BBS_SYS), proof_time=None, res=results(nym=bytes(32), drop=("age-range-123",)))),
    q=query(items=[BBS_PSEUDONYM], meta=BBS_META), client=cm((BBS_SYS,)))
err("pseudonym_prf_unknown", "pseudonym_prf_unknown", "The request's pseudonym item has no known prf, so no length can be demanded: refused.",
    vp(P(res=results(drop=("age-range-123",)))),
    q=query(items=[{"fn_id": "pseudonym", "return": "nym", "params": {"config": "known-offender-matching-ssc"}}]))

# ---- order of checks: the first failure in the documented order wins ------------------
err("order_unknown_member_before_missing", "presentation_unknown_member", "An unknown member and a missing member: unknown first.", vp(P(omit=("proof",), extra=[("zzz", NULL)])))
err("order_missing_before_wrong_type", "presentation_member_missing", "A missing member and a wrong type: missing first.", vp(P(omit=("results",), system_id=NULL)))
err("order_wrong_type_before_offer", "presentation_member_wrong_type", "A wrong-typed proof and an unoffered system_id: type first.", vp(P(system_id=tstr("urn:other"), proof=tstr("x"))))
err("order_offer_before_proof_empty", "system_id_not_offered", "An unoffered system_id and an empty proof: offer first.", vp(P(system_id=tstr("urn:other"), proof=bstr(b""))))
err("order_proof_empty_before_issuer_key_set", "proof_empty", "An empty proof and an empty issuer_key_set: proof first.", vp(P(proof=bstr(b""), keys=arr([]))))
err("order_issuer_key_set_before_proof_time", "issuer_key_set_empty", "An empty issuer_key_set and a missing proof_time: key set first.", vp(P(keys=arr([]), proof_time=None)))
err("order_issuer_key_count_before_element", "issuer_key_set_too_many", "Nine elements, the first not bytes: the count is checked first.", vp(P(keys=arr([tstr("x")] + [bstr(KEY)] * 8))))
err("order_proof_time_before_handles", "proof_time_missing", "A missing proof_time and a missing handle: proof_time first.", vp(P(proof_time=None, res=results(drop=("nym",)))))
err("order_unexpected_before_missing_handle", "result_handle_unexpected", "An extra handle and a missing handle: unexpected first.", vp(P(res=mp([(tstr("zzz"), TRUE), (tstr("age-range-123"), TRUE)]))))
err("order_handles_before_values", "result_handle_missing", "A missing handle and a bad value: handles first.", vp(P(res=mp([(tstr("nym"), tstr("bad"))]))))
err("order_values_in_request_order", "result_wrong_type", "Both values are bad: the first request item (the pseudonym) is reported.", vp(P(res=results(nym_raw=tstr("x"), age=FALSE))))
err("order_values_in_request_order_reversed", "result_not_satisfied", "The same bad results with the age item first in the request: the age item is reported.",
    vp(P(res=results(nym_raw=tstr("x"), age=FALSE))), q=query(items=[AGE, PSEUDONYM]))
err("order_envelope_before_presentation", "presentations_multiple_not_allowed", "Two presentations, the first malformed: the count is refused before either is read.", {"nym_attestation": [b64u(b""), b64u(b"")]})
err("order_first_presentation_first", "cbor_malformed", "Presentation 0 is malformed and presentation 1 is also bad: presentation 0 is reported.", {"nym_attestation": [b64u(b""), 5]}, q=query(multiple=True))

# ---- write ------------------------------------------------------------------------------
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    if f.endswith(".json"): os.remove(os.path.join(OUT, f))
for name in sorted(VECTORS):
    v = VECTORS[name]
    with open(os.path.join(OUT, name + ".json"), "w") as fh:
        json.dump(v, fh, indent=2, ensure_ascii=False); fh.write("\n")
print(len(VECTORS), "vectors")
