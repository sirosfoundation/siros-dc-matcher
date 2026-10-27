//! The request as the credential picker reads it: a DC API request entry whose protocol is one
//! of OpenID4VP 1.0, A.1, in the shape its label names, with its DCQL query.
//!
//! # Nothing here is verified
//!
//! A signed request's payload is decoded **without checking the signature**. The picker has
//! no crypto and no randomness, runs under a hard size budget in someone else's process, and
//! is not the trust boundary: the wallet runs intake (`crate::intake`, feature `crypto`) at
//! selection time, before anything is disclosed. The picker decides only which entries to draw.
//! Nothing read here may be treated as authenticated by anything downstream.

mod shape;

use serde_json::Value;
use siros_codec::json::JsonTextError;
use siros_codec::Base64Error;
use siros_dcql::{DcqlQuery, QueryError};

use crate::protocol::Protocol;

/// Why one protocol's request data yielded no request.
///
/// Each variant means "decline this entry", which lets the caller fall through to another
/// entry the verifier offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoQuery {
    /// The entry carried no `data`.
    NoData,
    /// `data` had neither `dcql_query` nor anything shaped like a JWS.
    NoQueryAndNoRequest,
    /// `data.request` is present but is neither a string nor an object.
    RequestNotAJwsOrObject,
    /// A JWS JSON Serialization object is present but carries no string `payload`.
    JwsObjectHasNoPayload,
    /// The data carries a `request` under the unsigned protocol, or an inline query under a
    /// signed one: the label and the shape disagree.
    ShapeDoesNotMatchProtocol,
    /// `data.request` of a signed request is no compact JWS.
    NotACompactJws(CompactFault),
    /// The payload segment is no unpadded base64url the picker decodes.
    PayloadNotBase64url(PayloadFault),
    /// The payload decoded, but is not JSON.
    PayloadNotJson(JsonTextError),
    /// The payload is JSON but carries no `dcql_query`.
    PayloadHasNoDcqlQuery,
    /// A `dcql_query` was found but does not parse as DCQL.
    Malformed(QueryError),
    /// The protocol is none of the three of OpenID4VP 1.0, A.1.
    NoParser,
}

impl NoQuery {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoData => "no_data",
            Self::NoQueryAndNoRequest => "no_query_and_no_request",
            Self::RequestNotAJwsOrObject => "request_not_a_jws_or_object",
            Self::JwsObjectHasNoPayload => "jws_object_has_no_payload",
            Self::ShapeDoesNotMatchProtocol => "shape_does_not_match_protocol",
            Self::NotACompactJws(_) => "not_a_compact_jws",
            Self::PayloadNotBase64url(_) => "payload_not_base64url",
            Self::PayloadNotJson(_) => "payload_not_json",
            Self::PayloadHasNoDcqlQuery => "payload_has_no_dcql_query",
            Self::Malformed(_) => "dcql_query_malformed",
            Self::NoParser => "protocol_unsupported",
        }
    }

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
            Self::NotACompactJws(_) => "data.request is not a compact JWS".into(),
            Self::PayloadNotBase64url(_) => "JWS payload is not unpadded base64url".into(),
            Self::PayloadNotJson(_) => "JWS payload is not JSON".into(),
            Self::PayloadHasNoDcqlQuery => "JWS payload has no `dcql_query`".into(),
            Self::Malformed(e) => format!("dcql_query failed to parse: {e}"),
            Self::NoParser => "no parser for this protocol in this build".into(),
        }
    }
}

/// How `data.request` of an `openid4vp-v1-signed` request fails to be a compact JWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactFault {
    /// `request` is absent or not a string.
    NotString,
    /// The string has other than three segments (RFC 7515, Section 7.1).
    Segments,
    /// The header segment is empty.
    EmptyHeader,
    /// The payload segment is empty.
    EmptyPayload,
}

/// Why a JWS payload segment yields no bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFault {
    /// The segment is longer than the picker decodes.
    TooLong,
    /// The segment is not unpadded base64url.
    Encoding(Base64Error),
}

/// One DC API request entry, read without verification (OpenID4VP 1.0, Appendix A).
///
/// Its existence guarantees a protocol of A.1 and a `data` in the shape that protocol names,
/// carrying a `dcql_query` that DCQL parses. Every value comes from a payload whose signature
/// nobody checked.
#[derive(Debug, Clone, PartialEq)]
pub struct UnverifiedRequest {
    protocol: Protocol,
    /// The request object without its `dcql_query`, which `query` holds.
    object: Value,
    query: DcqlQuery,
}

impl UnverifiedRequest {
    /// Reads one entry: its protocol `label` and its `data`.
    ///
    /// # Errors
    ///
    /// [`NoQuery`]: [`NoQuery::NoParser`] for a label outside A.1, otherwise what the data
    /// breaks.
    pub fn read(label: &str, data: &Value) -> Result<Self, NoQuery> {
        let protocol = Protocol::from_label(label).ok_or(NoQuery::NoParser)?;
        let mut object = shape::request_object(protocol, data)?.into_owned();
        let raw = object
            .as_object_mut()
            .and_then(|o| o.remove("dcql_query"))
            .ok_or(NoQuery::PayloadHasNoDcqlQuery)?;
        let query = DcqlQuery::parse(&raw).map_err(NoQuery::Malformed)?;
        Ok(Self {
            protocol,
            object,
            query,
        })
    }

    /// The first entry of the DC API request `request`, `{"requests": [{"protocol", "data"},
    /// …]}`, whose label `registered` accepts and whose data reads.
    ///
    /// The request is a list because one DC API call can offer the same request under several
    /// protocols. An entry that does not read is skipped, so a later readable one wins.
    #[must_use]
    pub fn first_registered(request: &[u8], registered: &dyn Fn(&str) -> bool) -> Option<Self> {
        serde_json::from_slice::<Value>(request)
            .ok()?
            .get("requests")?
            .as_array()?
            .iter()
            .find_map(|entry| {
                let label = entry.get("protocol")?.as_str()?;
                if !registered(label) {
                    return None;
                }
                Self::read(label, entry.get("data")?).ok()
            })
    }

    /// The protocol of the entry.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// The request object's `client_id`, when it is a string.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.object.get("client_id")?.as_str()
    }

    /// The request object's `expected_origins`, when it is an array of strings.
    #[must_use]
    pub fn expected_origins(&self) -> Option<Vec<&str>> {
        self.object
            .get("expected_origins")?
            .as_array()?
            .iter()
            .map(Value::as_str)
            .collect()
    }

    /// The request object's `client_metadata`, whole.
    #[must_use]
    pub fn client_metadata(&self) -> Option<&Value> {
        self.object.get("client_metadata")
    }

    /// The request object's `dcql_query`.
    #[must_use]
    pub fn query(&self) -> &DcqlQuery {
        &self.query
    }
}

/// Why no entry of the DC API request `request` reads, one clause per entry.
///
/// `registered` is the same filter [`UnverifiedRequest::first_registered`] takes. The picker
/// shows this only when the wallet registered with its debug flag set.
#[must_use]
pub fn diagnose(request: &[u8], registered: &dyn Fn(&str) -> bool) -> String {
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
    requests
        .iter()
        .map(|entry| entry_diagnosis(entry, registered))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Why the request entry `entry` does not read, as one clause.
fn entry_diagnosis(entry: &Value, registered: &dyn Fn(&str) -> bool) -> String {
    let protocol = entry
        .get("protocol")
        .and_then(|p| p.as_str())
        .unwrap_or("<missing protocol>");
    if !registered(protocol) {
        return format!("{protocol}: not in registered profile");
    }
    let Some(data) = entry.get("data") else {
        return format!("{protocol}: {}", NoQuery::NoData.reason());
    };
    match strict_query(protocol, data) {
        Ok(q) => format!(
            "{protocol}: dcql_query parsed ({} credential queries) - should not have reached here",
            q.credentials().len()
        ),
        Err(e) => format!("{protocol}: {}", e.reason()),
    }
}

/// The entry's `dcql_query` as DCQL proper: what the diagnostic names, since a query the
/// picker matched produces no diagnostic.
fn strict_query(label: &str, data: &Value) -> Result<DcqlQuery, NoQuery> {
    let protocol = Protocol::from_label(label).ok_or(NoQuery::NoParser)?;
    let object = shape::request_object(protocol, data)?;
    let raw = object
        .get("dcql_query")
        .ok_or(NoQuery::PayloadHasNoDcqlQuery)?;
    DcqlQuery::parse(raw).map_err(NoQuery::Malformed)
}
