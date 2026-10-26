//! Session binding: the `Handover` of the channel (nym_auth catalogue, "Binding") and, for the
//! mdoc systems, the message the device key signs and its digest e2 (system rulebooks,
//! Section 5).

use siros_codec::cbor::Value as Cbor;

use crate::verifier_id::sha256;

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
