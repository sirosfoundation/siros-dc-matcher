//! The refusals of reading and of disclosing, each with a stable code.

use siros_codec::cbor::CborError;

/// Why a stored credential is no mdoc [`Mdoc::parse`](crate::Mdoc::parse) reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("mso_mdoc: {}", self.code())]
pub enum MdocError {
    /// The text is not base64url without padding.
    Encoding,
    /// The bytes are not one CBOR item the strict reader accepts.
    #[error("mso_mdoc: cbor: {0}")]
    Cbor(#[source] CborError),
    /// The top level is no `IssuerSigned`, `Document` or one-document `DeviceResponse`.
    Envelope,
    /// `issuerAuth` is not an untagged `COSE_Sign1` with a protected header, a payload and a
    /// signature as byte strings.
    IssuerAuth,
    /// The protected header names no algorithm (label 1) as an integer.
    Algorithm,
    /// The unprotected header has no `x5chain` (label 33) of DER certificates.
    X5chain,
    /// The payload is not `#6.24(bstr .cbor MobileSecurityObject)`.
    Payload,
    /// The MSO has no `docType`, or the `Document` names another.
    DocType,
    /// `digestAlgorithm` is not `SHA-256`, `SHA-384` or `SHA-512`.
    DigestAlgorithm,
    /// `valueDigests` is no non-empty map from namespaces to non-empty maps from `digestID` to
    /// digests of the algorithm's length, each namespace and `digestID` once.
    ValueDigests,
    /// `deviceKeyInfo.deviceKey` is no P-256 `COSE_Key` with 32-byte coordinates.
    DeviceKey,
    /// `keyAuthorizations` breaks its CDDL, repeats a name, or names a namespace both whole and
    /// by its elements.
    KeyAuthorizations,
    /// `validityInfo` lacks `signed`, `validFrom` or `validUntil` as a 20-character `tdate`, or
    /// `validFrom` precedes `signed` or does not precede `validUntil`.
    Validity,
    /// `nameSpaces` is no non-empty map from namespaces to non-empty arrays of
    /// `IssuerSignedItemBytes`, each namespace once.
    NameSpaces,
    /// An `IssuerSignedItem` lacks `digestID`, `random`, `elementIdentifier` or `elementValue`.
    Item,
    /// A namespace holds an element identifier twice.
    RepeatedElement,
    /// The digest of an `IssuerSignedItemBytes` is not the one `valueDigests` lists under its
    /// namespace and `digestID`.
    ItemDigest,
}

impl MdocError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Encoding => "encoding",
            Self::Cbor(_) => "cbor",
            Self::Envelope => "envelope",
            Self::IssuerAuth => "issuer_auth",
            Self::Algorithm => "algorithm",
            Self::X5chain => "x5chain",
            Self::Payload => "payload",
            Self::DocType => "doc_type",
            Self::DigestAlgorithm => "digest_algorithm",
            Self::ValueDigests => "value_digests",
            Self::DeviceKey => "device_key",
            Self::KeyAuthorizations => "key_authorizations",
            Self::Validity => "validity",
            Self::NameSpaces => "name_spaces",
            Self::Item => "item",
            Self::RepeatedElement => "repeated_element",
            Self::ItemDigest => "item_digest",
        }
    }
}

/// Why [`Mdoc::disclose`](crate::Mdoc::disclose) refuses a selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("mso_mdoc disclosure: {}", self.code())]
pub enum DisclosureError {
    /// A selected element is no item of the mdoc.
    UnknownElement,
    /// An element is selected twice.
    RepeatedSelection,
    /// The MSO's `KeyAuthorizations` do not authorize a `DeviceSigned` element (OpenID4VP 1.0,
    /// B.2.1).
    Unauthorized,
    /// A `DeviceSigned` element is given twice.
    RepeatedDeviceElement,
}

impl DisclosureError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownElement => "unknown_element",
            Self::RepeatedSelection => "repeated_selection",
            Self::Unauthorized => "unauthorized_device_element",
            Self::RepeatedDeviceElement => "repeated_device_element",
        }
    }
}
