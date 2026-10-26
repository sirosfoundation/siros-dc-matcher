//! The nym_auth form of an ISO/IEC 18013-5 attestation (nym_auth catalogue, "Attestation" and
//! "ISO/IEC 18013-5 encoding"), read from a stored credential.

use std::fmt;

use siros_codec::cbor::Value;
use siros_codec::date::{Date, DateTime};
use siros_mdoc::{DigestAlgorithm, IssuerSignedItem, Mdoc, MdocError, P256Key};

use crate::catalogue::MDOC_DOCTYPE;

/// ES256 (RFC 9053, Section 2.1).
const ES256: i64 = -7;

/// A credential as the Wallet stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCredential {
    /// The Wallet's identifier.
    pub id: String,
    /// The credential format, `mso_mdoc` here.
    pub format: String,
    /// The credential as issued: base64url, without padding, of an `IssuerSigned`, of a
    /// `Document`, or of a `DeviceResponse` with one document.
    pub data: String,
    /// The identifier of the device key, for `sign`.
    pub kid: String,
}

/// Why an `mso_mdoc` is unreadable, or out of the nym_auth form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormError {
    /// The credential is no mdoc.
    Mdoc(MdocError),
    /// The issuer does not sign with ES256 (`{1: -7}`).
    Algorithm,
    /// The issuer's signature is not 64 bytes.
    Signature,
    /// `digestAlgorithm` is not `SHA-256`.
    DigestAlgorithm,
    /// The nym_auth namespace is missing.
    NameSpace,
    /// An element other than `birth_date`, `ssc` and `psc`, or a `psc` that is not 32 bytes.
    Element,
    /// `birth_date` is missing or not a tag-1004 `full-date`.
    BirthDate,
    /// `ssc` is missing or not 32 bytes.
    Ssc,
}

impl FormError {
    /// A stable identifier: the mdoc's, or the rule of the nym_auth form.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Mdoc(e) => e.code(),
            Self::Algorithm => "issuer_algorithm",
            Self::Signature => "issuer_signature_length",
            Self::DigestAlgorithm => "nym_auth_digest_algorithm",
            Self::NameSpace => "nym_auth_name_space",
            Self::Element => "nym_auth_element",
            Self::BirthDate => "birth_date",
            Self::Ssc => "ssc",
        }
    }
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mdoc(e) => e.fmt(f),
            _ => write!(f, "nym_auth mdoc: {}", self.code()),
        }
    }
}

impl std::error::Error for FormError {}

/// A signed data element and the bytes its digest covers.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedElement<T> {
    value: T,
    bytes: Vec<u8>,
}

impl<T> SignedElement<T> {
    /// The element's value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// `IssuerSignedItemBytes`: the tag-24 item, as issued.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A nym_auth attestation in the ISO/IEC 18013-5 form.
#[derive(Clone, PartialEq, Eq)]
pub struct NymAuthMdoc {
    issuer_signed: Vec<u8>,
    sig_structure: Vec<u8>,
    issuer_signature: [u8; 64],
    document_signer: Vec<u8>,
    device_key: P256Key,
    valid_from: DateTime,
    valid_until: DateTime,
    birth_date: SignedElement<Date>,
    ssc: SignedElement<[u8; 32]>,
    psc: Option<SignedElement<[u8; 32]>>,
}

impl NymAuthMdoc {
    /// The `IssuerSigned` structure, as issued.
    pub fn issuer_signed(&self) -> &[u8] {
        &self.issuer_signed
    }

    /// The COSE `Sig_structure` the issuer signed.
    pub fn sig_structure(&self) -> &[u8] {
        &self.sig_structure
    }

    /// The issuer's ES256 signature, `r ‖ s`.
    pub fn issuer_signature(&self) -> &[u8; 64] {
        &self.issuer_signature
    }

    /// The Document Signer certificate, DER: the first of `x5chain`.
    pub fn document_signer(&self) -> &[u8] {
        &self.document_signer
    }

    /// `deviceKeyInfo.deviceKey`.
    pub fn device_key(&self) -> &P256Key {
        &self.device_key
    }

    /// `validityInfo.validFrom`.
    pub fn valid_from(&self) -> DateTime {
        self.valid_from
    }

    /// `validityInfo.validUntil`.
    pub fn valid_until(&self) -> DateTime {
        self.valid_until
    }

    /// `birth_date`.
    pub fn birth_date(&self) -> &SignedElement<Date> {
        &self.birth_date
    }

    /// `ssc`.
    pub fn ssc(&self) -> &SignedElement<[u8; 32]> {
        &self.ssc
    }

    /// `psc`, when issued.
    pub fn psc(&self) -> Option<&SignedElement<[u8; 32]>> {
        self.psc.as_ref()
    }
}

/// Shows nothing: `birth_date`, `ssc` and `psc` are undisclosable.
impl<T> fmt::Debug for SignedElement<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedElement").finish_non_exhaustive()
    }
}

/// Shows the Document Signer, the device key and the validity: the elements are undisclosable.
impl fmt::Debug for NymAuthMdoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NymAuthMdoc")
            .field("document_signer", &self.document_signer)
            .field("device_key", &self.device_key)
            .field("valid_from", &self.valid_from)
            .field("valid_until", &self.valid_until)
            .finish_non_exhaustive()
    }
}

/// Whether a stored credential is a nym_auth mdoc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// It is.
    NymAuth(Box<NymAuthMdoc>),
    /// It is an mdoc of another `docType`.
    OtherDocType,
}

/// Reads `data` of a stored `mso_mdoc` credential.
///
/// # Errors
///
/// [`FormError`]: what makes the credential unreadable or puts it out of the nym_auth form.
pub fn read(data: &str) -> Result<Reading, FormError> {
    let mdoc = Mdoc::parse(data).map_err(FormError::Mdoc)?;
    if mdoc.doc_type() != MDOC_DOCTYPE {
        return Ok(Reading::OtherDocType);
    }
    let auth = mdoc.issuer_auth();
    if auth.algorithm() != ES256 {
        return Err(FormError::Algorithm);
    }
    let issuer_signature: [u8; 64] = auth
        .signature()
        .try_into()
        .map_err(|_| FormError::Signature)?;
    let mso = mdoc.mso();
    if mso.digest_algorithm() != DigestAlgorithm::Sha256 {
        return Err(FormError::DigestAlgorithm);
    }
    let name_space = mdoc
        .name_spaces()
        .iter()
        .find(|n| n.name() == MDOC_DOCTYPE)
        .ok_or(FormError::NameSpace)?;
    let elements = read_elements(name_space.items())?;
    Ok(Reading::NymAuth(Box::new(NymAuthMdoc {
        issuer_signed: mdoc.issuer_signed().to_vec(),
        sig_structure: auth.sig_structure().to_vec(),
        issuer_signature,
        document_signer: auth.document_signer().to_vec(),
        device_key: *mso.device_key(),
        valid_from: mso.validity().valid_from(),
        valid_until: mso.validity().valid_until(),
        birth_date: elements.birth_date.ok_or(FormError::BirthDate)?,
        ssc: elements.ssc.ok_or(FormError::Ssc)?,
        psc: elements.psc,
    })))
}

#[derive(Default)]
struct Elements {
    birth_date: Option<SignedElement<Date>>,
    ssc: Option<SignedElement<[u8; 32]>>,
    psc: Option<SignedElement<[u8; 32]>>,
}

/// The nym_auth namespace: `birth_date`, `ssc` and an optional `psc`. The mdoc holds each
/// element identifier once.
fn read_elements(items: &[IssuerSignedItem]) -> Result<Elements, FormError> {
    let mut elements = Elements::default();
    for item in items {
        let bytes = item.bytes().to_vec();
        match item.identifier() {
            "birth_date" => {
                let value = full_date(item.value()).ok_or(FormError::BirthDate)?;
                elements.birth_date = Some(SignedElement { value, bytes });
            }
            "ssc" => elements.ssc = Some(commitment(item.value(), bytes, FormError::Ssc)?),
            "psc" => elements.psc = Some(commitment(item.value(), bytes, FormError::Element)?),
            _ => return Err(FormError::Element),
        }
    }
    Ok(elements)
}

/// `full-date = #6.1004(tstr)` (RFC 8943).
fn full_date(value: &Value) -> Option<Date> {
    match value {
        Value::Tag(1004, text) => match text.as_ref() {
            Value::Text(text) => Date::parse(text),
            _ => None,
        },
        _ => None,
    }
}

fn commitment(
    value: &Value,
    bytes: Vec<u8>,
    error: FormError,
) -> Result<SignedElement<[u8; 32]>, FormError> {
    let Value::Bytes(value) = value else {
        return Err(error);
    };
    let value: [u8; 32] = value.as_slice().try_into().map_err(|_| error)?;
    Ok(SignedElement { value, bytes })
}
