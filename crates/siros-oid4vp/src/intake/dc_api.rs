//! Intake of a DC API request (OpenID4VP 1.0, Appendix A).

use serde_json::{Map, Value};

use super::request::{self, Arrival};
use super::signature::{self, Verifier};
use super::trust::{self, KeyMaterial, TrustSubject};
use super::{Answers, Halt, IntakeError};
use crate::client_id::ClientId;
use crate::jose::{self, Signed};
use crate::protocol::Protocol;
use crate::unverified::UnverifiedRequest;
use crate::verified::VerifiedRequest;

/// Intake of the DC API request `request` from `origin`.
pub(super) fn intake(
    request: &[u8],
    origin: &str,
    now_unix: u64,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let envelope: Value =
        serde_json::from_slice(request).map_err(|_| IntakeError::EnvelopeUnreadable)?;
    let (protocol, data) = entry(&envelope).ok_or(IntakeError::EnvelopeUnreadable)?;
    match protocol {
        Protocol::Unsigned => {
            let params = data.as_object().ok_or(IntakeError::EnvelopeUnreadable)?;
            let trusted = trust::verdict(
                answers,
                TrustSubject::Origin(origin.to_owned()),
                KeyMaterial::None,
            )?;
            Ok(request::verified(
                params,
                Arrival::DcApiUnsigned { origin, trusted },
            )?)
        }
        Protocol::Signed => {
            let jws = data
                .get("request")
                .and_then(Value::as_str)
                .ok_or(IntakeError::EnvelopeUnreadable)?;
            let (signed, payload) = jose::compact(jws)?;
            let params = request_object(&payload)?;
            let client_id = params
                .get("client_id")
                .and_then(Value::as_str)
                .ok_or(IntakeError::ClientIdMissing)?;
            let verifier =
                signature::authenticate(&signed, ClientId::parse(client_id)?, now_unix, answers)?;
            Ok(request::verified(
                &params,
                Arrival::DcApiSigned { origin, verifier },
            )?)
        }
        Protocol::Multisigned => {
            // The serialization is `data.request`, or `data` itself.
            let jws = match data.get("request") {
                Some(request @ Value::Object(_)) => request,
                _ => data,
            };
            let payload_b64 = jws
                .get("payload")
                .and_then(Value::as_str)
                .ok_or(IntakeError::JwsMalformed)?;
            let payload =
                siros_codec::base64url::decode(payload_b64).ok_or(IntakeError::JwsMalformed)?;
            let params = request_object(&payload)?;
            // A.3.2.2: `client_id` travels in each signature's protected header only.
            if params.contains_key("client_id") {
                return Err(IntakeError::ClientIdInPayload.into());
            }
            let signatures = jws
                .get("signatures")
                .and_then(Value::as_array)
                .ok_or(IntakeError::JwsMalformed)?;
            let verifier = first_qualifying(signatures, payload_b64, now_unix, answers)?;
            Ok(request::verified(
                &params,
                Arrival::DcApiSigned { origin, verifier },
            )?)
        }
    }
}

/// The entry the credential picker answers: the first that reads as an
/// [`UnverifiedRequest`].
fn entry(envelope: &Value) -> Option<(Protocol, &Value)> {
    envelope
        .get("requests")?
        .as_array()?
        .iter()
        .find_map(|entry| {
            let label = entry.get("protocol")?.as_str()?;
            let data = entry.get("data")?;
            let read = UnverifiedRequest::read(label, data).ok()?;
            Some((read.protocol(), data))
        })
}

fn request_object(payload: &[u8]) -> Result<Map<String, Value>, IntakeError> {
    match serde_json::from_slice(payload) {
        Ok(Value::Object(object)) => Ok(object),
        _ => Err(IntakeError::RequestObjectNotObject),
    }
}

/// The Verifier of the first signature that verifies and is trusted, or of the first that
/// verifies when none is trusted.
///
/// A signature that breaks a rule does not qualify, and the next is tried. A host result that
/// does not fit its effect stops intake.
fn first_qualifying(
    signatures: &[Value],
    payload_b64: &str,
    now_unix: u64,
    answers: &mut Answers<'_>,
) -> Result<Verifier, Halt> {
    let mut first_untrusted = None;
    for entry in signatures {
        match qualify(entry, payload_b64, now_unix, answers) {
            Ok(verifier) if verifier.trusted => return Ok(verifier),
            Ok(verifier) => {
                first_untrusted.get_or_insert(verifier);
            }
            Err(Halt::Failed(_)) => {}
            Err(halt) => return Err(halt),
        }
    }
    first_untrusted.ok_or_else(|| IntakeError::NoVerifiableSignature.into())
}

/// One signature object `{"protected", "signature"}` of the JWS JSON Serialization.
fn qualify(
    entry: &Value,
    payload_b64: &str,
    now_unix: u64,
    answers: &mut Answers<'_>,
) -> Result<Verifier, Halt> {
    let text = |name: &str| entry.get(name).and_then(Value::as_str);
    let (Some(protected), Some(signature)) = (text("protected"), text("signature")) else {
        return Err(IntakeError::JwsMalformed.into());
    };
    let signed = Signed::parse(protected, payload_b64, signature)?;
    let client_id = signed
        .text("client_id")
        .ok_or(IntakeError::ClientIdMissing)?;
    signature::authenticate(&signed, ClientId::parse(client_id)?, now_unix, answers)
}
