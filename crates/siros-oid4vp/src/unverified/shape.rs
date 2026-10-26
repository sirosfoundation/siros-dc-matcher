//! The request object of one entry, in the one shape its protocol allows.
//!
//! The protocol label is what a wallet uses to decide whether to verify a signature. A request
//! labelled unsigned that carries a JWS, read here and offered, would be consented to and then
//! handled as though it had never been signed; each label therefore accepts its own shape only.

use std::borrow::Cow;

use serde_json::Value;
use siros_codec::base64url;

use super::NoQuery;
use crate::protocol::Protocol;

/// The request object an entry carries; it has a `dcql_query`. The unsigned shape borrows
/// `data` itself.
pub(super) fn request_object(protocol: Protocol, data: &Value) -> Result<Cow<'_, Value>, NoQuery> {
    match protocol {
        Protocol::Unsigned => match data.get("dcql_query") {
            Some(_) => Ok(Cow::Borrowed(data)),
            // A `request` here is a signed shape under the unsigned label.
            None if data.get("request").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
            None => Err(NoQuery::NoQueryAndNoRequest),
        },
        Protocol::Signed => match data.get("request") {
            Some(Value::String(jws)) => payload_object(compact_payload(jws)?),
            // An inline query under a signed label.
            None if data.get("dcql_query").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
            _ => Err(NoQuery::NotACompactJws),
        },
        Protocol::Multisigned => payload_object(json_payload(data)?),
    }
}

/// The request object inside a decoded, unverified JWS payload.
fn payload_object<'a>(payload: Vec<u8>) -> Result<Cow<'a, Value>, NoQuery> {
    let object: Value = serde_json::from_slice(&payload).map_err(|_| NoQuery::PayloadNotJson)?;
    if object.get("dcql_query").is_none() {
        return Err(NoQuery::PayloadHasNoDcqlQuery);
    }
    Ok(Cow::Owned(object))
}

/// The unverified payload of a JWS JSON Serialization object, under `data.request` or as
/// `data` itself.
fn json_payload(data: &Value) -> Result<Vec<u8>, NoQuery> {
    match data.get("request") {
        Some(request @ Value::Object(_)) => {
            json_serialization_payload(request, NoQuery::JwsObjectHasNoPayload)
        }
        // A string is a compact JWS, the `-signed` shape.
        Some(Value::String(_)) => Err(NoQuery::ShapeDoesNotMatchProtocol),
        // A number, a bool, null: present, and unable to carry a payload.
        Some(_) => Err(NoQuery::RequestNotAJwsOrObject),
        // An inline query under a signed label.
        None if data.get("dcql_query").is_some() => Err(NoQuery::ShapeDoesNotMatchProtocol),
        None => json_serialization_payload(data, NoQuery::NoQueryAndNoRequest),
    }
}

/// The middle segment of a compact JWS, decoded.
///
/// The serialization is always `header.payload.signature` (RFC 7515, Section 7.1). The
/// signature may be empty, as in RFC 7519, Section 6: whether such a request is acceptable is
/// intake's decision. Five segments is a JWE, whose second segment is an encrypted key.
///
/// `splitn` bounds the work by the meaningful segments: the input is verifier-controlled and
/// the picker has a time budget.
fn compact_payload(jws: &str) -> Result<Vec<u8>, NoQuery> {
    let mut segments = jws.splitn(4, '.');
    let header = segments.next();
    let payload = segments.next();
    let signature = segments.next();
    if segments.next().is_some() {
        return Err(NoQuery::NotACompactJws);
    }
    if signature.is_none() || header.is_none_or(str::is_empty) {
        return Err(NoQuery::NotACompactJws);
    }
    let Some(payload) = payload.filter(|p| !p.is_empty()) else {
        return Err(NoQuery::NotACompactJws);
    };
    decode_payload(payload)
}

/// The `payload` member of a JWS JSON Serialization object; `missing` when it has none.
fn json_serialization_payload(value: &Value, missing: NoQuery) -> Result<Vec<u8>, NoQuery> {
    let Some(Value::String(payload)) = value.get("payload") else {
        return Err(missing);
    };
    decode_payload(payload)
}

/// The largest JWS payload the picker decodes, in encoded bytes.
///
/// The picker runs in someone else's process, where running out of memory traps and a trap
/// reads as "no matching credential". A request object is a few kilobytes.
const MAX_PAYLOAD: usize = 256 * 1024;

fn decode_payload(payload: &str) -> Result<Vec<u8>, NoQuery> {
    if payload.len() > MAX_PAYLOAD {
        return Err(NoQuery::PayloadNotBase64url);
    }
    base64url::decode(payload).ok_or(NoQuery::PayloadNotBase64url)
}
