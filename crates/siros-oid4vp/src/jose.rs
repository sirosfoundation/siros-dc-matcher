//! JWS (RFC 7515) with ES256 (RFC 7518, Section 3.4), and P-256 public JWKs (RFC 7518,
//! Section 6.2.1).

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::PublicKey;
use serde_json::{Map, Value};
use siros_codec::base64url;

use crate::intake::IntakeError;

/// One signature over a payload: its JOSE Header and what it signs.
///
/// The header is the protected header alone: only integrity-protected parameters are read.
#[derive(Debug, Clone)]
pub(crate) struct Signed {
    header: Map<String, Value>,
    signing_input: String,
    signature: Signature,
}

/// A JWS Compact Serialization: the signature and the decoded payload.
pub(crate) fn compact(jws: &str) -> Result<(Signed, Vec<u8>), IntakeError> {
    let mut segments = jws.splitn(4, '.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(IntakeError::JwsMalformed);
    };
    let signed = Signed::parse(header, payload, signature)?;
    Ok((signed, decode(payload)?))
}

impl Signed {
    /// The signature `signature_b64` by the protected header `protected_b64` over the payload
    /// `payload_b64`, each as written in the serialization.
    pub(crate) fn parse(
        protected_b64: &str,
        payload_b64: &str,
        signature_b64: &str,
    ) -> Result<Self, IntakeError> {
        let header = match serde_json::from_slice(&decode(protected_b64)?) {
            Ok(Value::Object(header)) => header,
            _ => return Err(IntakeError::JwsMalformed),
        };
        let signature = Signature::from_slice(&decode(signature_b64)?)
            .map_err(|_| IntakeError::JwsMalformed)?;
        if header.get("alg").and_then(Value::as_str) != Some("ES256") {
            return Err(IntakeError::AlgorithmUnsupported);
        }
        // RFC 7515, Section 4.1.11: no extension is understood here.
        if header.contains_key("crit") {
            return Err(IntakeError::CriticalHeader);
        }
        Ok(Self {
            header,
            signing_input: format!("{protected_b64}.{payload_b64}"),
            signature,
        })
    }

    /// The protected header.
    pub(crate) fn header(&self) -> &Map<String, Value> {
        &self.header
    }

    /// A string Header Parameter.
    pub(crate) fn text(&self, name: &str) -> Option<&str> {
        self.header.get(name).and_then(Value::as_str)
    }

    /// Verifies the ES256 signature under `key`.
    pub(crate) fn verify(&self, key: &PublicKey) -> Result<(), IntakeError> {
        VerifyingKey::from(key)
            .verify(self.signing_input.as_bytes(), &self.signature)
            .map_err(|_| IntakeError::SignatureInvalid)
    }
}

fn decode(segment: &str) -> Result<Vec<u8>, IntakeError> {
    base64url::decode(segment).map_err(|_| IntakeError::JwsMalformed)
}

/// The key of a public JWK with `kty` `EC` and `crv` `P-256`, its coordinates 32 bytes each.
pub(crate) fn p256_key(jwk: &Value) -> Option<PublicKey> {
    let text = |name: &str| jwk.get(name).and_then(Value::as_str);
    if text("kty")? != "EC" || text("crv")? != "P-256" {
        return None;
    }
    let coordinate = |name: &str| {
        base64url::decode(text(name)?)
            .ok()
            .filter(|c| c.len() == 32)
    };
    let point = [vec![0x04], coordinate("x")?, coordinate("y")?].concat();
    PublicKey::from_sec1_bytes(&point).ok()
}
