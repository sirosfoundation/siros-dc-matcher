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
    parsed
        .get("requests")?
        .as_array()?
        .iter()
        .find_map(|entry| {
            let protocol = entry.get("protocol")?.as_str()?;
            let parser = profile.parser_for(protocol)?;
            let query = extract_query(parser, entry.get("data")?).ok()?;
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
/// # Errors
///
/// See [`NoQuery`]. Every variant means "decline this protocol", which lets the
/// caller fall through to another the verifier offered.
pub fn extract_query(parser: Parser, data: &Value) -> Result<DcqlQuery, NoQuery> {
    match parser {
        Parser::Openid4vpV1 => {
            if let Some(dcql) = data.get("dcql_query") {
                return parse_dcql(dcql);
            }
            let payload = signed_payload(data)?;
            let object: Value =
                serde_json::from_slice(&payload).map_err(|_| NoQuery::PayloadNotJson)?;
            let dcql = object
                .get("dcql_query")
                .ok_or(NoQuery::PayloadHasNoDcqlQuery)?;
            parse_dcql(dcql)
        }
        // ISO 18013-7 carries a CBOR DeviceRequest rather than DCQL, so it
        // needs its own reader rather than a different JSON pointer.
        Parser::IsoMdocApi => Err(NoQuery::NoParser),
    }
}

/// The unverified payload bytes of a signed or multisigned request.
///
/// Both `data.request` and `data` itself are accepted as the carrier of a JWS
/// JSON Serialization object: the reference matcher accepts the payload at the
/// top level of `data` too, and a verifier that sends it that way is not wrong
/// enough to refuse.
fn signed_payload(data: &Value) -> Result<Vec<u8>, NoQuery> {
    match data.get("request") {
        // Compact serialization: header.payload.signature.
        Some(Value::String(jws)) => compact_payload(jws),
        // JWS JSON Serialization, general or flattened.
        Some(Value::Object(_)) => json_serialization_payload(&data["request"]),
        _ => json_serialization_payload(data),
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
    let _header = segments.next();
    let payload = segments.next();
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
fn json_serialization_payload(value: &Value) -> Result<Vec<u8>, NoQuery> {
    let Some(Value::String(payload)) = value.get("payload") else {
        return Err(NoQuery::NoQueryAndNoRequest);
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
        match extract_query(parser, data) {
            Ok(q) => parts.push(format!(
                "{protocol}: dcql_query parsed ({} credential queries) - should not have reached here",
                q.credentials.len()
            )),
            Err(e) => parts.push(format!("{protocol}: {}", e.reason())),
        }
    }
    parts.join(" | ")
}
