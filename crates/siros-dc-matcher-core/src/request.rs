//! Reading the DC API request: which protocol to answer, and its DCQL query.
//!
//! In this crate rather than in the WASM binary because it is ordinary logic
//! over JSON with no host calls in it, and because in the binary it was
//! reachable only by running the real `matcher.wasm` under a WASI host — which
//! made every case below expensive to test and invisible to coverage.
//!
//! # The matcher does not verify signatures
//!
//! A signed request's payload is decoded here **without checking the
//! signature**, and that is deliberate rather than a shortcut. The matcher has
//! no crypto and no randomness, runs under a hard size budget in someone
//! else's process, and is not the trust boundary: the wallet verifies the JWS
//! at selection time, before anything is disclosed. What the matcher decides is
//! only which entries to draw in the picker.
//!
//! Reading an unverified payload to render a picker entry is what the reference
//! matcher does too. The rule it implies is worth stating: nothing in here may
//! be treated as authenticated by anything downstream.

use std::borrow::Cow;

use serde_json::Value;
use siros_dcql::DcqlQuery;

use crate::base64url;
use crate::profile::{MatchProfile, Parser};

/// Why one protocol's request data yielded no DCQL query.
///
/// Carried rather than collapsed into `None` so the debug diagnostic can say
/// which of these happened. "data has no `dcql_query`" is true of every signed
/// request and tells the reader nothing about why theirs was declined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoQuery {
    /// The protocol is in the profile, but the entry carried no `data`.
    NoData,
    /// `data` had neither `dcql_query` nor anything shaped like a JWS.
    NoQueryAndNoRequest,
    /// `data.request` is present but is neither a string nor an object, so
    /// there is nothing to decode — a different problem from its absence.
    RequestNotAJwsOrObject,
    /// A JWS JSON Serialization object is present but carries no string
    /// `payload` — again, present but undecodable rather than absent.
    JwsObjectHasNoPayload,
    /// The data carries a `request` under a protocol whose shape is an inline
    /// query, or an inline query under a signed one. The label and the shape
    /// disagree, which is a different problem from either being absent.
    ShapeDoesNotMatchProtocol,
    /// `data.request` is a string but not a compact JWS.
    NotACompactJws,
    /// The payload segment is not unpadded base64url.
    PayloadNotBase64url,
    /// The payload decoded, but is not JSON.
    PayloadNotJson,
    /// The payload is JSON but carries no `dcql_query`.
    PayloadHasNoDcqlQuery,
    /// A `dcql_query` was found but does not parse as DCQL.
    Malformed(String),
    /// The protocol has no reader in this build.
    NoParser,
}

impl NoQuery {
    /// One line for the picker's debug entry.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::NoData => "request entry has no `data`".into(),
            Self::NoQueryAndNoRequest => {
                "data has neither `dcql_query` nor a `request` to decode".into()
            }
            Self::RequestNotAJwsOrObject => {
                "data.request is neither a JWS string nor a JWS JSON object".into()
            }
            Self::JwsObjectHasNoPayload => {
                "the JWS JSON object has no string `payload` member".into()
            }
            Self::ShapeDoesNotMatchProtocol => {
                "the request shape does not match the protocol it is labelled with".into()
            }
            Self::NotACompactJws => "data.request is not a compact JWS".into(),
            Self::PayloadNotBase64url => "JWS payload is not unpadded base64url".into(),
            Self::PayloadNotJson => "JWS payload is not JSON".into(),
            Self::PayloadHasNoDcqlQuery => "JWS payload has no `dcql_query`".into(),
            Self::Malformed(e) => format!("dcql_query failed to parse: {e}"),
            Self::NoParser => "no parser for this protocol in this build".into(),
        }
    }
}

/// The first protocol in the request the profile supports *and* can read.
///
/// The request is a list because one DC API call can offer the same request
/// under several protocols and let the wallet pick. Taking the first
/// *supported* one rather than the first one is what makes that negotiation
/// work — and which protocols are supported comes from the registered profile,
/// so adding one costs a re-registration rather than a new binary.
///
/// "Can read" matters as much as "supports": a verifier that offers
/// `openid4vp-v1-signed` and `openid4vp-v1-unsigned` together gets an answer
/// from whichever this build can actually decode.
#[must_use]
pub fn first_supported_request(
    request: &[u8],
    profile: &MatchProfile,
) -> Option<(String, DcqlQuery)> {
    let parsed: Value = serde_json::from_slice(request).ok()?;
    first_supported_in(&parsed, profile)
}

/// [`first_supported_request`] for a caller that has already parsed the
/// envelope, so the JSON is not walked twice at an API boundary.
#[must_use]
pub fn first_supported_in(parsed: &Value, profile: &MatchProfile) -> Option<(String, DcqlQuery)> {
    // Entries whose query has no typed form (a `circuit_zk` request in the
    // rulebook-example shape) are skipped, exactly as they were when they were
    // a parse failure: this function can only return a `DcqlQuery`.
    let only_typed = |_: &str, _: bool, context: &RequestContext| context.dcql_query.is_some();
    let context = first_supported_context_in(parsed, profile, Some(&only_typed))?;
    let query = context.dcql_query?;
    Some((context.protocol, query))
}

/// What one request entry carries, as read from its (unverified) request
/// object.
///
/// # Nothing here is authenticated
///
/// Every field comes from a payload that was decoded **without checking its
/// signature** (see the module docs). `client_id`, `expected_origins` and
/// `client_metadata` in particular are exactly the values a signature is there
/// to protect, and the matcher is not the party that checks it. A caller that
/// enforces anything on them must do so after the wallet has verified the
/// request.
///
/// New fields may be added without a breaking change.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct RequestContext {
    /// The protocol label of the entry, e.g. `openid4vp-v1-signed`.
    pub protocol: String,
    /// Whether the label names a signed shape. This says how the request
    /// *arrived*, not that its signature is valid.
    pub signed: bool,
    /// The request object's `client_id`, if it is a string.
    pub client_id: Option<String>,
    /// The request object's `expected_origins`, if it is an array of strings.
    pub expected_origins: Option<Vec<String>>,
    /// The request object's `client_metadata`, whole, so that
    /// `vp_formats_supported` and anything else in it is available.
    pub client_metadata: Option<Value>,
    /// The request object's `dcql_query` exactly as sent.
    pub dcql_query_raw: Value,
    /// `dcql_query_raw` parsed as DCQL.
    ///
    /// `None` only for a query DCQL cannot represent but a `circuit_zk`
    /// credential query can: `claims` as an object, in the rulebook example
    /// shape. Such a request is read from `dcql_query_raw` instead.
    pub dcql_query: Option<DcqlQuery>,
}

/// A caller's say over which entry of `requests` is used: it receives the
/// protocol label, whether the entry is signed, and the extracted context.
pub type EntryFilter<'a> = &'a dyn Fn(&str, bool, &RequestContext) -> bool;

/// The first supported, readable entry in the request that `accept` allows,
/// with its full [`RequestContext`].
///
/// With `accept` as `None` this selects exactly what
/// [`first_supported_request`] does. With a predicate, an entry it rejects is
/// skipped and a later acceptable one can win, so a wallet that refuses some
/// entries (unsigned ones, say) still reaches an entry it does accept. If it
/// rejects every entry the result is `None`.
///
/// The matcher enforces nothing about signed protocols or `expected_origins`;
/// it exposes the values and this hook, and the policy is the caller's. See
/// [`RequestContext`] for why the values are not authenticated.
#[must_use]
pub fn first_supported_context(
    request: &[u8],
    profile: &MatchProfile,
    accept: Option<EntryFilter<'_>>,
) -> Option<RequestContext> {
    let parsed: Value = serde_json::from_slice(request).ok()?;
    first_supported_context_in(&parsed, profile, accept)
}

/// [`first_supported_context`] for a caller that has already parsed the
/// envelope.
#[must_use]
pub fn first_supported_context_in(
    parsed: &Value,
    profile: &MatchProfile,
    accept: Option<EntryFilter<'_>>,
) -> Option<RequestContext> {
    parsed
        .get("requests")?
        .as_array()?
        .iter()
        .find_map(|entry| {
            let protocol = entry.get("protocol")?.as_str()?;
            let parser = profile.parser_for(protocol)?;
            let context = extract_context(parser, protocol, entry.get("data")?).ok()?;
            match accept {
                Some(accept) if !accept(protocol, context.signed, &context) => None,
                _ => Some(context),
            }
        })
}

/// The [`RequestContext`] carried by one protocol's request data.
///
/// The same shape rules and the same errors as [`extract_query`], which is
/// this with everything but the parsed query dropped.
///
/// # Errors
///
/// See [`NoQuery`].
pub fn extract_context(
    parser: Parser,
    protocol: &str,
    data: &Value,
) -> Result<RequestContext, NoQuery> {
    let (object, signed) = request_object(parser, protocol, data)?;
    let raw = object
        .get("dcql_query")
        .ok_or(NoQuery::PayloadHasNoDcqlQuery)?;
    let dcql_query = parse_dcql_or_circuit_zk(raw)?;
    Ok(RequestContext {
        protocol: protocol.to_string(),
        signed,
        client_id: object
            .get("client_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        expected_origins: object
            .get("expected_origins")
            .and_then(Value::as_array)
            .and_then(|a| {
                a.iter()
                    .map(|o| o.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
            }),
        client_metadata: object.get("client_metadata").cloned(),
        dcql_query_raw: raw.clone(),
        dcql_query,
    })
}

/// The DCQL query carried by one protocol's request data.
///
/// Three shapes reach us, and the envelope around them is identical — only
/// `data` differs (OpenID4VP 1.0 Appendix A):
///
/// | protocol | `data` |
/// |---|---|
/// | `openid4vp-v1-unsigned` | the authorization request object, `dcql_query` inline |
/// | `openid4vp-v1-signed` | `{"request": "<header>.<payload>.<signature>"}` |
/// | `openid4vp-v1-multisigned` | `{"request": {"payload": "<base64url>", "signatures": [...]}}` |
///
/// Base64url-decoded, the signed payloads are the same JSON the unsigned form
/// carries directly.
///
/// # The shape must match the label
///
/// Which shapes are accepted follows the *protocol id*, not merely the parser.
/// All three OpenID4VP protocols share a parser, so without this a verifier
/// could label a request `openid4vp-v1-unsigned` and still send a JWS in
/// `data.request` — and the matcher would answer it, having read the query out
/// of a signed payload, while reporting the protocol as unsigned.
///
/// That matters because the protocol id is what a wallet uses to decide
/// whether to verify a signature. A request whose payload chose the
/// credentials, presented to the user, and then handled as though it had never
/// been signed, is a gap between what was consented to and what is checked.
///
/// # Errors
///
/// See [`NoQuery`]. Every variant means "decline this protocol", which lets the
/// caller fall through to another the verifier offered.
pub fn extract_query(parser: Parser, protocol: &str, data: &Value) -> Result<DcqlQuery, NoQuery> {
    let (object, _) = request_object(parser, protocol, data)?;
    parse_dcql(
        object
            .get("dcql_query")
            .ok_or(NoQuery::PayloadHasNoDcqlQuery)?,
    )
}

/// The request object an entry carries, and whether its protocol is a signed
/// shape. Enforces the shape-must-match-the-label rule; guarantees the object
/// has a `dcql_query`.
///
/// The object is `data` itself for the inline shape, so that case borrows.
fn request_object<'a>(
    parser: Parser,
    protocol: &str,
    data: &'a Value,
) -> Result<(Cow<'a, Value>, bool), NoQuery> {
    match parser {
        Parser::Openid4vpV1 => match Shape::of(protocol) {
            Shape::Inline => match data.get("dcql_query") {
                Some(_) => Ok((Cow::Borrowed(data), false)),
                // A `request` here means the verifier sent a signed shape
                // under a label whose shape is inline. Saying "no dcql_query"
                // would send whoever reads it looking for a missing key when
                // the request is right there under the wrong name.
                None if data.get("request").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
                None => Err(NoQuery::NoQueryAndNoRequest),
            },
            Shape::CompactJws => match data.get("request") {
                Some(Value::String(jws)) => payload_object(compact_payload(jws)?),
                // An inline query under a signed label is the mirror image of
                // the case above, and just as worth naming.
                None if data.get("dcql_query").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
                _ => Err(NoQuery::NotACompactJws),
            },
            Shape::JwsJson => payload_object(json_payload(data)?),
        },
        // ISO 18013-7 carries a CBOR DeviceRequest rather than DCQL, so it
        // needs its own reader rather than a different JSON pointer.
        Parser::IsoMdocApi => Err(NoQuery::NoParser),
    }
}

/// The one request shape a protocol id is allowed to arrive in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// The request object is `data` itself, `dcql_query` inline.
    Inline,
    /// `data.request` is a compact JWS.
    CompactJws,
    /// A JWS JSON Serialization object, under `data.request` or `data`.
    JwsJson,
}

impl Shape {
    /// Unrecognised ids get [`Shape::Inline`], the shape that requires no
    /// decoding of anything unverified. A profile naming its own OpenID4VP
    /// protocol is not thereby opting into signed payloads.
    fn of(protocol: &str) -> Self {
        match protocol {
            "openid4vp-v1-signed" => Self::CompactJws,
            "openid4vp-v1-multisigned" => Self::JwsJson,
            _ => Self::Inline,
        }
    }
}

/// The request object inside a decoded, unverified JWS payload. Always signed.
fn payload_object<'a>(payload: Vec<u8>) -> Result<(Cow<'a, Value>, bool), NoQuery> {
    let object: Value = serde_json::from_slice(&payload).map_err(|_| NoQuery::PayloadNotJson)?;
    if object.get("dcql_query").is_none() {
        return Err(NoQuery::PayloadHasNoDcqlQuery);
    }
    Ok((Cow::Owned(object), true))
}

/// The unverified payload of a JWS JSON Serialization object.
///
/// Both `data.request` and `data` itself are accepted as its carrier: the
/// reference matcher accepts the payload at the top level of `data` too, and a
/// verifier that sends it that way is not wrong enough to refuse.
fn json_payload(data: &Value) -> Result<Vec<u8>, NoQuery> {
    match data.get("request") {
        Some(Value::Object(_)) => {
            json_serialization_payload(&data["request"], NoQuery::JwsObjectHasNoPayload)
        }
        // A string here is a compact JWS, which is the `-signed` shape: the
        // label and the shape disagree, which is a mismatch rather than a
        // value of the wrong type.
        Some(Value::String(_)) => Err(NoQuery::ShapeDoesNotMatchProtocol),
        // A number, a bool, null — nothing that could carry a payload.
        // Distinguished from absence because "there is no request" sends
        // whoever is reading the diagnostic looking for a missing key that is
        // in fact right there.
        Some(_) => Err(NoQuery::RequestNotAJwsOrObject),
        // An inline query under a signed label, same as the compact-JWS branch
        // reports. Without this the symmetry breaks and one of the two
        // mismatches gets the vaguer reason.
        None if data.get("dcql_query").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
        None => json_serialization_payload(data, NoQuery::NoQueryAndNoRequest),
    }
}

/// The middle segment of a compact JWS.
///
/// Exactly three segments: the compact serialization is always
/// `header.payload.signature` (RFC 7515 §7.1). The signature may be *empty* —
/// that is RFC 7519 §6's unsecured token — because whether an unsecured request
/// is acceptable is the wallet's decision and not this one. The header and the
/// payload may not be empty, and a token that is malformed in that way would
/// otherwise produce a picker entry for a request the wallet rejects a moment
/// later.
///
/// Beyond the count, the header and signature are not inspected; the matcher is
/// not the party deciding whether a signature is acceptable. But five segments
/// is a JWE, whose second segment is an encrypted key rather than a payload:
/// decoding that would either fail with a misleading reason or, worse, succeed
/// on something that is not the request.
///
/// The work is bounded by `splitn`, not by the number of dots — this is
/// verifier-controlled input reaching a sandbox with a time budget, and
/// splitting on every one would allocate in proportion to the request.
fn compact_payload(jws: &str) -> Result<Vec<u8>, NoQuery> {
    // `splitn(4)`, and no collecting. The input is verifier-controlled and this
    // runs in a sandbox with a time budget, so the work has to be bounded by
    // the parts that mean something rather than by how many dots someone sent:
    // splitting on every one would allocate proportionally to the request.
    // A fourth piece existing at all is enough to know there were too many.
    let mut segments = jws.splitn(4, '.');
    let header = segments.next();
    let payload = segments.next();
    let signature = segments.next();
    // A fourth piece at all means more than three segments, whatever is in it —
    // enough to know this is not a compact JWS without splitting further.
    if segments.next().is_some() {
        return Err(NoQuery::NotACompactJws);
    }
    // Exactly three, and the header present. The *signature* may be empty:
    // that is the unsecured token of RFC 7519 §6, and whether an unsecured
    // request is acceptable is the wallet's decision rather than this one.
    if signature.is_none() || header.is_none_or(str::is_empty) {
        return Err(NoQuery::NotACompactJws);
    }
    let Some(payload) = payload.filter(|p| !p.is_empty()) else {
        return Err(NoQuery::NotACompactJws);
    };
    base64url::decode(payload).ok_or(NoQuery::PayloadNotBase64url)
}

/// The `payload` member of a JWS JSON Serialization object.
///
/// `missing` is the caller's, because the two callers mean different things by
/// a missing `payload`: under `data.request` it is a malformed signed request,
/// while at the top level of `data` it means this was not a signed request at
/// all. Reporting either as the other sends whoever reads the diagnostic
/// looking in the wrong place.
fn json_serialization_payload(value: &Value, missing: NoQuery) -> Result<Vec<u8>, NoQuery> {
    let Some(Value::String(payload)) = value.get("payload") else {
        return Err(missing);
    };
    base64url::decode(payload).ok_or(NoQuery::PayloadNotBase64url)
}

fn parse_dcql(value: &Value) -> Result<DcqlQuery, NoQuery> {
    serde_json::from_value(value.clone()).map_err(|e| NoQuery::Malformed(e.to_string()))
}

/// Parse a raw `dcql_query` as DCQL, tolerating `circuit_zk` credential queries
/// DCQL cannot represent.
///
/// The typed parser expects `claims` to be a sequence, and the `circuit_zk`
/// rulebook example puts an object there. When the typed parse fails, the query
/// is retried without its `circuit_zk` credentials: if the rest parses, the
/// failure was theirs and the result is `Ok(None)`, leaving the raw value for
/// the `circuit_zk` planner. A failure that is not theirs is still
/// [`NoQuery::Malformed`], so every other format behaves as before.
fn parse_dcql_or_circuit_zk(raw: &Value) -> Result<Option<DcqlQuery>, NoQuery> {
    let first_error = match serde_json::from_value::<DcqlQuery>(raw.clone()) {
        Ok(query) => return Ok(Some(query)),
        Err(e) => e,
    };
    let is_circuit_zk = |c: &Value| c.get("format").and_then(Value::as_str) == Some("circuit_zk");
    let (Some(credentials), Some(object)) = (
        raw.get("credentials").and_then(Value::as_array),
        raw.as_object(),
    ) else {
        return Err(NoQuery::Malformed(first_error.to_string()));
    };
    if !credentials.iter().any(is_circuit_zk) {
        return Err(NoQuery::Malformed(first_error.to_string()));
    }
    let mut rest = object.clone();
    rest.insert(
        "credentials".to_string(),
        Value::Array(
            credentials
                .iter()
                .filter(|c| !is_circuit_zk(c))
                .cloned()
                .collect(),
        ),
    );
    match serde_json::from_value::<DcqlQuery>(Value::Object(rest)) {
        Ok(_) => Ok(None),
        Err(_) => Err(NoQuery::Malformed(first_error.to_string())),
    }
}

/// Why [`first_supported_request`] found nothing to answer.
///
/// Only ever shown when the registered profile has `debug` set; the wallet
/// gates that on the app's own debuggable flag.
#[must_use]
pub fn diagnose(request: &[u8], profile: &MatchProfile) -> String {
    let parsed: Value = match serde_json::from_slice(request) {
        Ok(v) => v,
        Err(e) => return format!("request ({} bytes) is not valid JSON: {e}", request.len()),
    };
    let Some(requests) = parsed.get("requests").and_then(|r| r.as_array()) else {
        return "request JSON has no `requests` array".to_string();
    };
    if requests.is_empty() {
        return "`requests` array is empty".to_string();
    }

    let mut parts = Vec::new();
    for entry in requests {
        let protocol = entry
            .get("protocol")
            .and_then(|p| p.as_str())
            .unwrap_or("<missing protocol>");
        let Some(parser) = profile.parser_for(protocol) else {
            parts.push(format!("{protocol}: not in registered profile"));
            continue;
        };
        let Some(data) = entry.get("data") else {
            parts.push(format!("{protocol}: {}", NoQuery::NoData.reason()));
            continue;
        };
        match extract_query(parser, protocol, data) {
            Ok(q) => parts.push(format!(
                "{protocol}: dcql_query parsed ({} credential queries) - should not have reached here",
                q.credentials.len()
            )),
            Err(e) => parts.push(format!("{protocol}: {}", e.reason())),
        }
    }
    parts.join(" | ")
}
