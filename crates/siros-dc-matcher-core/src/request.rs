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
    parsed
        .get("requests")?
        .as_array()?
        .iter()
        .find_map(|entry| {
            let protocol = entry.get("protocol")?.as_str()?;
            let parser = profile.parser_for(protocol)?;
            let query = extract_query(parser, protocol, entry.get("data")?).ok()?;
            Some((protocol.to_string(), query))
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
    match parser {
        Parser::Openid4vpV1 => match Shape::of(protocol) {
            Shape::Inline => match data.get("dcql_query") {
                Some(dcql) => parse_dcql(dcql),
                // A `request` here means the verifier sent a signed shape
                // under a label whose shape is inline. Saying "no dcql_query"
                // would send whoever reads it looking for a missing key when
                // the request is right there under the wrong name.
                None if data.get("request").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
                None => Err(NoQuery::NoQueryAndNoRequest),
            },
            Shape::CompactJws => match data.get("request") {
                Some(Value::String(jws)) => from_payload(compact_payload(jws)?),
                // An inline query under a signed label is the mirror image of
                // the case above, and just as worth naming.
                None if data.get("dcql_query").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
                _ => Err(NoQuery::NotACompactJws),
            },
            Shape::JwsJson => from_payload(json_payload(data)?),
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

/// The DCQL query inside a decoded, unverified JWS payload.
fn from_payload(payload: Vec<u8>) -> Result<DcqlQuery, NoQuery> {
    let object: Value = serde_json::from_slice(&payload).map_err(|_| NoQuery::PayloadNotJson)?;
    let dcql = object
        .get("dcql_query")
        .ok_or(NoQuery::PayloadHasNoDcqlQuery)?;
    parse_dcql(dcql)
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
/// The header and the signature are not inspected — the matcher is not the
/// party deciding whether a signature is acceptable — but the segment *count*
/// is, in both directions.
///
/// Two or three. Three is a JWS; two is an unsecured token whose payload is
/// still the request object we need. Five is a JWE, and there the second
/// segment is an encrypted key rather than a payload: decoding it would either
/// fail with a misleading reason or, worse, succeed on something that is not
/// the request. A verifier sending a JWE is doing something this matcher has no
/// answer for, and saying so is better than guessing.
fn compact_payload(jws: &str) -> Result<Vec<u8>, NoQuery> {
    // `splitn(4)`, and no collecting. The input is verifier-controlled and this
    // runs in a sandbox with a time budget, so the work has to be bounded by
    // the parts that mean something rather than by how many dots someone sent:
    // splitting on every one would allocate proportionally to the request.
    // A fourth piece existing at all is enough to know there were too many.
    let mut segments = jws.splitn(4, '.');
    // The header is not inspected, but it has to be there. A token starting
    // with `.` is malformed, and offering a picker entry for it means the user
    // consents to something the wallet will reject afterwards.
    let header = segments.next();
    let payload = segments.next();
    if header.is_none_or(str::is_empty) {
        return Err(NoQuery::NotACompactJws);
    }
    let _signature = segments.next();
    // A fourth piece at all means there were more than three segments, whatever
    // is in it — enough to know this is not a JWS without splitting further.
    if segments.next().is_some() {
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
