//! `DeviceSigned` elements and the data the device key signs (ISO/IEC 18013-5, 8.3.2.1.2.2 and
//! 9.1.3).

use siros_codec::cbor::Value;
use siros_dcql::DocType;

use crate::signature::{SessionTranscript, SigStructure};

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
    #[must_use]
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
#[must_use]
pub fn device_signing_input(
    session_transcript: &SessionTranscript,
    doc_type: &DocType,
    name_spaces: &DeviceNameSpaces,
) -> SigStructure {
    let authentication = Value::Array(vec![
        Value::text("DeviceAuthentication"),
        Value::Encoded(session_transcript.as_bytes().to_vec()),
        Value::text(doc_type.as_str()),
        Value::Encoded(name_spaces.as_cbor().to_vec()),
    ]);
    let bytes = Value::Tag(24, Box::new(Value::Bytes(authentication.encode())));
    SigStructure::new(
        Value::Array(vec![
            Value::text("Signature1"),
            Value::Bytes(PROTECTED_ES256.to_vec()),
            Value::Bytes(Vec::new()),
            Value::Bytes(bytes.encode()),
        ])
        .encode(),
    )
}
