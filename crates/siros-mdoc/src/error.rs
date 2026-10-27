//! The refusals of reading and of disclosing, each with a stable code and its cause.

use std::fmt;

use siros_codec::cbor::CborError;
use siros_codec::member::MemberFault;
use siros_codec::Base64Error;

use crate::names::{DigestId, NameSpace};

/// Why a stored credential is no mdoc [`Mdoc::parse`](crate::Mdoc::parse) reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdocError {
    /// The text is not base64url without padding.
    Encoding(Base64Error),
    /// The bytes are not one CBOR item the strict reader accepts.
    Cbor(CborError),
    /// The top level is no `IssuerSigned`, `Document` or one-document `DeviceResponse`.
    Envelope(EnvelopeFault),
    /// `issuerAuth` is not an untagged `COSE_Sign1` with a protected header, a payload and a
    /// signature as byte strings.
    IssuerAuth(IssuerAuthFault),
    /// The protected header names no algorithm (label 1) as an integer.
    Algorithm(AlgorithmFault),
    /// The unprotected header has no `x5chain` (label 33) of DER certificates.
    X5chain(MemberFault),
    /// The payload is not `#6.24(bstr .cbor MobileSecurityObject)`.
    Payload(PayloadFault),
    /// The MSO has no `docType`, or the `Document` names another.
    DocType(DocTypeFault),
    /// `digestAlgorithm` is not `SHA-256`, `SHA-384` or `SHA-512`.
    DigestAlgorithm(NameFault),
    /// `valueDigests` is no non-empty map from namespaces to non-empty maps from `digestID` to
    /// digests of the algorithm's length, each namespace and `digestID` once.
    ValueDigests(ValueDigestsFault),
    /// `deviceKeyInfo.deviceKey` is no P-256 `COSE_Key` with 32-byte coordinates.
    DeviceKey(DeviceKeyFault),
    /// `keyAuthorizations` breaks its CDDL, repeats a name, or names a namespace both whole and
    /// by its elements.
    KeyAuthorizations(KeyAuthorizationsFault),
    /// `validityInfo` lacks `signed`, `validFrom` or `validUntil` as a 20-character `tdate`, or
    /// `validFrom` precedes `signed` or does not precede `validUntil`.
    Validity(ValidityFault),
    /// `nameSpaces` is no non-empty map from namespaces to non-empty arrays of
    /// `IssuerSignedItemBytes`, each namespace once.
    NameSpaces(NameSpacesFault),
    /// An `IssuerSignedItem` lacks `digestID`, `random`, `elementIdentifier` or `elementValue`.
    Item(ItemFault),
    /// A namespace holds an element identifier twice.
    RepeatedElement,
    /// The digest of an `IssuerSignedItemBytes` is not the one `valueDigests` lists under its
    /// namespace and `digestID`.
    ItemDigest,
}

/// Why the top level is no envelope [`Mdoc::parse`](crate::Mdoc::parse) reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnvelopeFault {
    /// `documents` holds this many documents, where one is read.
    Documents(usize),
    /// The `Document` has no `issuerSigned`.
    IssuerSigned,
}

/// Why `issuerAuth` is no `COSE_Sign1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssuerAuthFault {
    /// `IssuerSigned` has no `issuerAuth`.
    Absent,
    /// It is not an array of four items.
    NotSign1,
    /// The protected header is not a byte string.
    Protected,
    /// The payload is not a byte string.
    Payload,
    /// The signature is not a byte string.
    Signature,
}

/// Why the protected header names no algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmFault {
    /// The header is not one CBOR item.
    Header(CborError),
    /// The header has no integer under label 1.
    Absent,
}

/// Why the payload is no MSO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFault {
    /// The payload is not one CBOR item.
    Cbor(CborError),
    /// It is not a byte string under tag 24.
    NotTagged,
    /// The tagged bytes are not one CBOR item.
    Mso(CborError),
}

/// Why the `docType` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DocTypeFault {
    /// The MSO has no `docType` text.
    Mso,
    /// The `Document` has no `docType` text.
    Document,
    /// The `Document` names another `docType` than its MSO.
    Mismatch,
}

/// Why a member names nothing this crate knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameFault {
    /// It is absent or not text.
    Member(MemberFault),
    /// It names none of the values this crate reads.
    Unknown,
}

/// Why `valueDigests` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ValueDigestsFault {
    /// `valueDigests` is no non-empty map.
    Member(MemberFault),
    /// A namespace is not text.
    NameSpace,
    /// The namespace's digests are no non-empty map.
    Digests(NameSpace, MemberFault),
    /// A `digestID` of the namespace is not an unsigned integer.
    DigestId(NameSpace),
    /// The digest under this `digestID` is not a byte string.
    Digest(NameSpace, DigestId),
    /// The digest under this `digestID` has this many bytes, another length than the
    /// algorithm's.
    DigestLength(NameSpace, DigestId, usize),
    /// The namespace lists this `digestID` twice.
    RepeatedDigestId(NameSpace, DigestId),
    /// The map holds this namespace twice.
    RepeatedNameSpace(NameSpace),
}

/// Why `deviceKeyInfo.deviceKey` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceKeyFault {
    /// The MSO has no `deviceKeyInfo`.
    Info,
    /// `deviceKeyInfo` has no `deviceKey`.
    Absent,
    /// `kty` (label 1) is not 2, EC2.
    KeyType,
    /// `crv` (label -1) is not 1, P-256.
    Curve,
    /// `x` (label -2) or `y` (label -3) is not a 32-byte string.
    Coordinate,
}

/// Why a list of names in `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NamesFault {
    /// It is no non-empty array.
    Member(MemberFault),
    /// A name is not text.
    NotText,
    /// It holds this name twice.
    Repeated(String),
}

/// Why `keyAuthorizations` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyAuthorizationsFault {
    /// It is not a map.
    NotMap,
    /// `nameSpaces`.
    NameSpaces(NamesFault),
    /// `dataElements` is no non-empty map.
    DataElements(MemberFault),
    /// A namespace of `dataElements` is not text.
    NameSpace,
    /// The element identifiers of this namespace.
    Elements(NameSpace, NamesFault),
    /// This namespace is in `nameSpaces` and in `dataElements`.
    Overlap(NameSpace),
    /// `dataElements` holds this namespace twice.
    RepeatedNameSpace(NameSpace),
}

/// A time of `validityInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidityTime {
    /// `signed`.
    Signed,
    /// `validFrom`.
    ValidFrom,
    /// `validUntil`.
    ValidUntil,
}

impl ValidityTime {
    /// The member's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Signed => "signed",
            Self::ValidFrom => "validFrom",
            Self::ValidUntil => "validUntil",
        }
    }
}

/// Why `validityInfo` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidityFault {
    /// The MSO has no `validityInfo`.
    Absent,
    /// This time is absent or no 20-character `tdate`.
    Time(ValidityTime),
    /// `validFrom` precedes `signed`, or does not precede `validUntil`.
    Order,
}

/// Why `nameSpaces` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NameSpacesFault {
    /// `nameSpaces` is no non-empty map.
    Member(MemberFault),
    /// A namespace is not text.
    NameNotText,
    /// The map holds this namespace twice.
    Repeated(NameSpace),
    /// The namespace's items are no non-empty array.
    Items(NameSpace, MemberFault),
    /// An item of the namespace is no byte string under tag 24.
    NotTagged(NameSpace),
}

/// A member of `IssuerSignedItem`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemMember {
    /// `digestID`, an unsigned integer.
    DigestId,
    /// `random`, a byte string.
    Random,
    /// `elementIdentifier`, text.
    ElementIdentifier,
    /// `elementValue`.
    ElementValue,
}

/// Why an `IssuerSignedItem` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemFault {
    /// The tagged bytes are not one CBOR item.
    Cbor(CborError),
    /// This member is absent or of another CBOR type.
    Member(ItemMember),
}

impl MdocError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Encoding(_) => "encoding",
            Self::Cbor(_) => "cbor",
            Self::Envelope(_) => "envelope",
            Self::IssuerAuth(_) => "issuer_auth",
            Self::Algorithm(_) => "algorithm",
            Self::X5chain(_) => "x5chain",
            Self::Payload(_) => "payload",
            Self::DocType(_) => "doc_type",
            Self::DigestAlgorithm(_) => "digest_algorithm",
            Self::ValueDigests(_) => "value_digests",
            Self::DeviceKey(_) => "device_key",
            Self::KeyAuthorizations(_) => "key_authorizations",
            Self::Validity(_) => "validity",
            Self::NameSpaces(_) => "name_spaces",
            Self::Item(_) => "item",
            Self::RepeatedElement => "repeated_element",
            Self::ItemDigest => "item_digest",
        }
    }
}

impl fmt::Display for MdocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(e) => write!(f, "mso_mdoc: cbor: {e}"),
            _ => write!(f, "mso_mdoc: {}: {self:?}", self.code()),
        }
    }
}

impl std::error::Error for MdocError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(e) => Some(e),
            Self::Cbor(e)
            | Self::Algorithm(AlgorithmFault::Header(e))
            | Self::Payload(PayloadFault::Cbor(e) | PayloadFault::Mso(e))
            | Self::Item(ItemFault::Cbor(e)) => Some(e),
            _ => None,
        }
    }
}

/// Why [`Mdoc::disclose`](crate::Mdoc::disclose) refuses a selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownElement => "unknown_element",
            Self::RepeatedSelection => "repeated_selection",
            Self::Unauthorized => "unauthorized_device_element",
            Self::RepeatedDeviceElement => "repeated_device_element",
        }
    }
}

impl fmt::Display for DisclosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mso_mdoc disclosure: {}", self.code())
    }
}

impl std::error::Error for DisclosureError {}
