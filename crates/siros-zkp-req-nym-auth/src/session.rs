//! Session binding: the `Handover` of the channel (nym_auth catalogue, "Binding") and, for the
//! mdoc systems, the message the device key signs and its digest e2 (system rulebooks,
//! Section 5).

use std::fmt;

use serde_json::Value;
use siros_codec::cbor::{self, Value as Cbor};

use crate::verifier_id::sha256;

/// The CBOR `Handover` of the channel a request arrived on (OpenID4VP 1.0, B.2.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handover {
    encoded: Vec<u8>,
}

/// Why bytes are not a `Handover` of OpenID4VP 1.0, B.2.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandoverInvalid;

impl fmt::Display for HandoverInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an OpenID4VP Handover")
    }
}

impl std::error::Error for HandoverInvalid {}

impl Handover {
    /// `OpenID4VPDCAPIHandover = ["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce,
    /// jwkThumbprint]))]` (OpenID4VP 1.0, B.2.6.2). The response is always encrypted, so the
    /// thumbprint is always present.
    pub fn dc_api(origin: &str, nonce: &str, jwk_thumbprint: &[u8; 32]) -> Self {
        let info = Cbor::Array(vec![
            Cbor::text(origin),
            Cbor::text(nonce),
            Cbor::Bytes(jwk_thumbprint.to_vec()),
        ]);
        Self::of("OpenID4VPDCAPIHandover", &info)
    }

    /// `OpenID4VPHandover = ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce,
    /// jwkThumbprint, response_uri]))]` (OpenID4VP 1.0, B.2.6.1).
    pub fn redirect(
        client_id: &str,
        nonce: &str,
        jwk_thumbprint: &[u8; 32],
        response_uri: &str,
    ) -> Self {
        let info = Cbor::Array(vec![
            Cbor::text(client_id),
            Cbor::text(nonce),
            Cbor::Bytes(jwk_thumbprint.to_vec()),
            Cbor::text(response_uri),
        ]);
        Self::of("OpenID4VPHandover", &info)
    }

    fn of(name: &str, info: &Cbor) -> Self {
        let handover = Cbor::Array(vec![
            Cbor::text(name),
            Cbor::Bytes(sha256(&info.encode()).to_vec()),
        ]);
        Self {
            encoded: handover.encode(),
        }
    }

    /// A `Handover` a host encoded: one of the two arrays of B.2.6, with a 32-byte digest.
    ///
    /// # Errors
    ///
    /// [`HandoverInvalid`] for any other bytes.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, HandoverInvalid> {
        let item = cbor::decode(bytes).map_err(|_| HandoverInvalid)?;
        let valid = match item.as_array() {
            Some([name, digest]) => {
                matches!(
                    name.as_text(),
                    Some("OpenID4VPHandover" | "OpenID4VPDCAPIHandover")
                ) && digest.as_bytes().is_some_and(|d| d.len() == 32)
            }
            _ => false,
        };
        if !valid {
            return Err(HandoverInvalid);
        }
        Ok(Self {
            encoded: bytes.to_vec(),
        })
    }

    /// The encoded `Handover`.
    pub fn as_cbor(&self) -> &[u8] {
        &self.encoded
    }

    /// `SessionTranscript = [null, null, Handover]`, encoded.
    pub fn session_transcript(&self) -> Vec<u8> {
        [&[0x83, 0xf6, 0xf6][..], &self.encoded].concat()
    }
}

/// The COSE `Sig_structure` the device key signs with ES256 (system rulebooks, Section 5):
///
/// ```text
/// DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript,
///                                               docType, #6.24(bstr .cbor {})])
/// message = ["Signature1", h'A10126', h'', DeviceAuthenticationBytes]
/// ```
pub fn device_message(session_transcript: &[u8], doc_type: &str) -> Vec<u8> {
    let authentication = Cbor::Array(vec![
        Cbor::text("DeviceAuthentication"),
        Cbor::Encoded(session_transcript.to_vec()),
        Cbor::text(doc_type),
        Cbor::Tag(24, Box::new(Cbor::Bytes(vec![0xa0]))),
    ]);
    let bytes = Cbor::Tag(24, Box::new(Cbor::Bytes(authentication.encode())));
    Cbor::Array(vec![
        Cbor::text("Signature1"),
        Cbor::Bytes(vec![0xa1, 0x01, 0x26]),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(bytes.encode()),
    ])
    .encode()
}

/// e2: the SHA-256 of [`device_message`].
pub fn challenge_digest(session_transcript: &[u8], doc_type: &str) -> [u8; 32] {
    sha256(&device_message(session_transcript, doc_type))
}

/// The JWK SHA-256 Thumbprint (RFC 7638) of an elliptic-curve key: the digest of
/// `{"crv":…,"kty":"EC","x":…,"y":…}` with no whitespace. `None` for a key of another type or
/// without these members as strings.
pub fn ec_jwk_thumbprint(jwk: &Value) -> Option<[u8; 32]> {
    if jwk.get("kty")?.as_str()? != "EC" {
        return None;
    }
    let member = |name: &str| jwk.get(name).and_then(Value::as_str);
    let canonical = serde_json::json!({
        "crv": member("crv")?,
        "kty": "EC",
        "x": member("x")?,
        "y": member("y")?,
    });
    // serde_json writes object members in key order without whitespace, as RFC 7638 asks.
    Some(sha256(canonical.to_string().as_bytes()))
}
