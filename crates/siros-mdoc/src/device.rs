//! `DeviceSigned` elements and the data the device key signs (ISO/IEC 18013-5, 8.3.2.1.2.2 and
//! 9.1.3).

use sha2::{Digest, Sha256};
use siros_codec::cbor::Value;

/// The protected header of an ES256 `COSE_Sign1`: `{1: -7}`.
pub(crate) const PROTECTED_ES256: [u8; 3] = [0xa1, 0x01, 0x26];

/// `DeviceNameSpacesBytes = #6.24(bstr .cbor {* NameSpace => {+ DataElementIdentifier =>
/// DataElementValue}})`, encoded once for the signing input and the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceNameSpaces {
    encoded: Vec<u8>,
}

impl DeviceNameSpaces {
    /// No element.
    pub fn empty() -> Self {
        Self::of(Value::Map(Vec::new()))
    }

    fn of(name_spaces: Value) -> Self {
        let bytes = Value::Tag(24, Box::new(Value::Bytes(name_spaces.encode())));
        Self {
            encoded: bytes.encode(),
        }
    }

    /// The encoded `DeviceNameSpacesBytes`.
    pub(crate) fn as_cbor(&self) -> &[u8] {
        &self.encoded
    }
}

/// The COSE `Sig_structure` the device key signs with ES256 for `deviceSignature`, whose payload
/// is detached (ISO/IEC 18013-5, 9.1.3.4 and 9.1.3.6):
///
/// ```text
/// DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication", SessionTranscript,
///                                               DocType, DeviceNameSpacesBytes])
/// Sig_structure = ["Signature1", h'A10126', h'', DeviceAuthenticationBytes]
/// ```
///
/// `session_transcript` is the encoded `SessionTranscript`.
pub fn device_signing_input(
    session_transcript: &[u8],
    doc_type: &str,
    name_spaces: &DeviceNameSpaces,
) -> Vec<u8> {
    let authentication = Value::Array(vec![
        Value::text("DeviceAuthentication"),
        Value::Encoded(session_transcript.to_vec()),
        Value::text(doc_type),
        Value::Encoded(name_spaces.as_cbor().to_vec()),
    ]);
    let bytes = Value::Tag(24, Box::new(Value::Bytes(authentication.encode())));
    Value::Array(vec![
        Value::text("Signature1"),
        Value::Bytes(PROTECTED_ES256.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(bytes.encode()),
    ])
    .encode()
}

/// The SHA-256 of [`device_signing_input`]: the message hash of the ES256 signature.
pub fn device_signing_digest(
    session_transcript: &[u8],
    doc_type: &str,
    name_spaces: &DeviceNameSpaces,
) -> [u8; 32] {
    Sha256::digest(device_signing_input(
        session_transcript,
        doc_type,
        name_spaces,
    ))
    .into()
}
