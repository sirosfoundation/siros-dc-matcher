//! An X.509 certificate (RFC 5280), as issuer trust reads it: its names, validity, key,
//! basicConstraints, AuthorityKeyIdentifier and signature.

use std::fmt;

use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode, Header, Reader, SliceReader, Tag};
use p256::ecdsa::signature::Verifier;
use siros_codec::date::DateTime;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use crate::authority::{KeyIdentifier, KeyIdentifierError};

/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `secp256r1` (RFC 5480).
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `secp384r1` (RFC 5480).
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// `ecdsa-with-SHA256` (RFC 5758).
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// `ecdsa-with-SHA384` (RFC 5758).
const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// `id-ce-basicConstraints` (RFC 5280, Section 4.2.1.9).
const BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
/// `id-ce-authorityKeyIdentifier` (RFC 5280, Section 4.2.1.1).
const AUTHORITY_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.35");
/// `id-ce-subjectKeyIdentifier` (RFC 5280, Section 4.2.1.2).
const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// A certificate's issuer or subject name: its DER encoding. Two names are one when their
/// encodings are.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DistinguishedName(Vec<u8>);

impl DistinguishedName {
    /// The DER encoding.
    #[must_use]
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

/// A DER X.509 certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    algorithm: SignatureAlgorithm,
    issuer: DistinguishedName,
    subject: DistinguishedName,
    not_before: DateTime,
    not_after: DateTime,
    key: SubjectKey,
    authority_key_identifier: Option<KeyIdentifier>,
    subject_key_identifier: Option<KeyIdentifier>,
    role: CertificateRole,
}

/// The algorithm a certificate is signed with, of those TR3 accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureAlgorithm {
    /// `ecdsa-with-SHA256`, without parameters.
    EcdsaSha256,
    /// `ecdsa-with-SHA384`, without parameters.
    EcdsaSha384,
    /// Another algorithm, or one with parameters.
    Other,
}

/// The subject's public key, of the key types TR3 verifies with.
#[derive(Debug, Clone)]
enum SubjectKey {
    /// A P-256 key, with its SEC 1 encoding.
    P256(p256::ecdsa::VerifyingKey, Vec<u8>),
    /// A P-384 key.
    P384(p384::ecdsa::VerifyingKey),
    /// A key of another type.
    Other,
}

/// Whether a certificate's subject is a certificate authority (basicConstraints, RFC 5280,
/// Section 4.2.1.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateRole {
    /// `cA` is TRUE: the subject may sign certificates.
    Ca,
    /// basicConstraints is absent, or `cA` is FALSE.
    EndEntity,
}

/// A time of a certificate's validity period (RFC 5280, Section 4.1.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidityTime {
    /// `notBefore`.
    NotBefore,
    /// `notAfter`.
    NotAfter,
}

/// A name of a certificate (RFC 5280, Section 4.1.2.4 and 4.1.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameField {
    /// `issuer`.
    Issuer,
    /// `subject`.
    Subject,
}

/// Why a subject key declared on P-256 or P-384 is no key of its curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyFault {
    /// `subjectPublicKey` is a BIT STRING of a partial byte.
    Bits,
    /// The bytes are no SEC 1 point of P-256.
    P256,
    /// The bytes are no SEC 1 point of P-384.
    P384,
}

/// Why a key identifier extension gives no keyIdentifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIdentifierFault {
    /// The extension does not decode.
    Der(der::Error),
    /// The keyIdentifier is no keyIdentifier.
    KeyIdentifier(KeyIdentifierError),
}

/// Why bytes are no certificate issuer trust reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateError {
    /// The bytes are not one DER X.509 certificate.
    Der(der::Error),
    /// `signatureAlgorithm` differs from the `signature` field of `tbsCertificate` (RFC 5280,
    /// Section 4.1.1.2).
    AlgorithmMismatch,
    /// The signature is not a BIT STRING of whole bytes.
    Signature,
    /// This name does not encode.
    Name(NameField, der::Error),
    /// This time of the validity period lies outside 0000 to 9999.
    Validity(ValidityTime),
    /// The subject's key is declared P-256 or P-384 and is no key of that curve.
    PublicKey(PublicKeyFault),
    /// The certificate holds the extension of this identifier twice (RFC 5280, Section 4.2).
    ExtensionRepeated(ObjectIdentifier),
    /// basicConstraints does not decode.
    BasicConstraints(der::Error),
    /// The AuthorityKeyIdentifier extension gives no keyIdentifier.
    AuthorityKeyIdentifier(KeyIdentifierFault),
    /// The SubjectKeyIdentifier extension gives no keyIdentifier.
    SubjectKeyIdentifier(KeyIdentifierFault),
}

impl CertificateError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Der(_) => "certificate_der",
            Self::AlgorithmMismatch => "certificate_algorithm_mismatch",
            Self::Signature => "certificate_signature",
            Self::Name(..) => "certificate_name",
            Self::Validity(_) => "certificate_validity",
            Self::PublicKey(_) => "certificate_public_key",
            Self::ExtensionRepeated(_) => "certificate_extension_repeated",
            Self::BasicConstraints(_) => "certificate_basic_constraints",
            Self::AuthorityKeyIdentifier(_) => "certificate_authority_key_identifier",
            Self::SubjectKeyIdentifier(_) => "certificate_subject_key_identifier",
        }
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for CertificateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Der(e)
            | Self::Name(_, e)
            | Self::BasicConstraints(e)
            | Self::AuthorityKeyIdentifier(KeyIdentifierFault::Der(e))
            | Self::SubjectKeyIdentifier(KeyIdentifierFault::Der(e)) => Some(e),
            Self::AuthorityKeyIdentifier(KeyIdentifierFault::KeyIdentifier(e))
            | Self::SubjectKeyIdentifier(KeyIdentifierFault::KeyIdentifier(e)) => Some(e),
            Self::AlgorithmMismatch
            | Self::Signature
            | Self::Validity(_)
            | Self::PublicKey(_)
            | Self::ExtensionRepeated(_) => None,
        }
    }
}

/// Why a certificate is not issued by another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssuanceRefusal {
    /// The certificate names another issuer than the other's subject.
    IssuerName,
    /// The certificate's signature algorithm is neither `ecdsa-with-SHA256` nor
    /// `ecdsa-with-SHA384` without parameters.
    Algorithm,
    /// The issuer's key is of another type or curve than the signature algorithm takes: P-256
    /// for SHA-256, P-384 for SHA-384.
    IssuerKey,
    /// The signature is no DER `ECDSA-Sig-Value` of the issuer's curve.
    SignatureEncoding,
    /// The signature does not verify under the issuer's key.
    Signature,
}

impl IssuanceRefusal {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::IssuerName => "issuer_name",
            Self::Algorithm => "signature_algorithm",
            Self::IssuerKey => "signature_issuer_key",
            Self::SignatureEncoding => "signature_encoding",
            Self::Signature => "signature",
        }
    }
}

impl fmt::Display for IssuanceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for IssuanceRefusal {}

impl Certificate {
    /// The certificate `der`.
    ///
    /// # Errors
    ///
    /// [`CertificateError`]: the first rule the bytes break.
    pub fn parse(der: &[u8]) -> Result<Self, CertificateError> {
        let certificate = x509_cert::Certificate::from_der(der).map_err(CertificateError::Der)?;
        let tbs_certificate = &certificate.tbs_certificate;
        if certificate.signature_algorithm != tbs_certificate.signature {
            return Err(CertificateError::AlgorithmMismatch);
        }
        let extensions = match &tbs_certificate.extensions {
            Some(extensions) => Extensions::read(extensions)?,
            None => Extensions::NONE,
        };
        let name = |field: NameField, name: &x509_cert::name::Name| {
            name.to_der()
                .map(DistinguishedName)
                .map_err(|error| CertificateError::Name(field, error))
        };
        let validity = &tbs_certificate.validity;
        Ok(Self {
            der: der.to_vec(),
            tbs: tbs_bytes(der).map_err(CertificateError::Der)?.to_vec(),
            signature: certificate
                .signature
                .as_bytes()
                .ok_or(CertificateError::Signature)?
                .to_vec(),
            algorithm: SignatureAlgorithm::of(&certificate.signature_algorithm),
            issuer: name(NameField::Issuer, &tbs_certificate.issuer)?,
            subject: name(NameField::Subject, &tbs_certificate.subject)?,
            not_before: time(validity.not_before, ValidityTime::NotBefore)?,
            not_after: time(validity.not_after, ValidityTime::NotAfter)?,
            key: SubjectKey::read(&tbs_certificate.subject_public_key_info)
                .map_err(CertificateError::PublicKey)?,
            authority_key_identifier: extensions.authority_key_identifier,
            subject_key_identifier: extensions.subject_key_identifier,
            role: extensions.role,
        })
    }

    /// The DER bytes.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The keyIdentifier of the AuthorityKeyIdentifier extension, when the certificate has one
    /// with a keyIdentifier.
    #[must_use]
    pub fn authority_key_identifier(&self) -> Option<&KeyIdentifier> {
        self.authority_key_identifier.as_ref()
    }

    /// The keyIdentifier of the SubjectKeyIdentifier extension, when the certificate has one.
    #[must_use]
    pub fn subject_key_identifier(&self) -> Option<&KeyIdentifier> {
        self.subject_key_identifier.as_ref()
    }

    /// The issuer's name.
    #[must_use]
    pub fn issuer(&self) -> &DistinguishedName {
        &self.issuer
    }

    /// The subject's name.
    #[must_use]
    pub fn subject(&self) -> &DistinguishedName {
        &self.subject
    }

    /// Whether the subject is a certificate authority.
    #[must_use]
    pub fn role(&self) -> CertificateRole {
        self.role
    }

    /// The SEC 1 encoding of the subject's key, when it is a P-256 key.
    #[must_use]
    pub fn p256_key(&self) -> Option<&[u8]> {
        match &self.key {
            SubjectKey::P256(_, sec1) => Some(sec1),
            SubjectKey::P384(_) | SubjectKey::Other => None,
        }
    }

    /// Whether `time` lies in the validity period, both ends included (RFC 5280, Section
    /// 4.1.2.5).
    #[must_use]
    pub(crate) fn valid_at(&self, time: DateTime) -> bool {
        self.not_before <= time && time <= self.not_after
    }

    /// Whether the certificate names `signer`'s subject as its issuer.
    pub(crate) fn names_as_issuer(&self, signer: &Self) -> bool {
        self.issuer == signer.subject
    }

    /// Whether `issuer` issued the certificate: the certificate names `issuer`'s subject as its
    /// issuer, and `issuer`'s key verifies its signature with ECDSA P-256 and SHA-256 or P-384
    /// and SHA-384.
    ///
    /// # Errors
    ///
    /// [`IssuanceRefusal`]: the first of these that fails.
    pub(crate) fn issued_by(&self, issuer: &Self) -> Result<(), IssuanceRefusal> {
        if !self.names_as_issuer(issuer) {
            return Err(IssuanceRefusal::IssuerName);
        }
        match (self.algorithm, &issuer.key) {
            (SignatureAlgorithm::Other, _) => Err(IssuanceRefusal::Algorithm),
            (SignatureAlgorithm::EcdsaSha256, SubjectKey::P256(key, _)) => {
                let signature = p256::ecdsa::DerSignature::from_bytes(&self.signature)
                    .map_err(|_| IssuanceRefusal::SignatureEncoding)?;
                key.verify(&self.tbs, &signature)
                    .map_err(|_| IssuanceRefusal::Signature)
            }
            (SignatureAlgorithm::EcdsaSha384, SubjectKey::P384(key)) => {
                let signature = p384::ecdsa::DerSignature::from_bytes(&self.signature)
                    .map_err(|_| IssuanceRefusal::SignatureEncoding)?;
                key.verify(&self.tbs, &signature)
                    .map_err(|_| IssuanceRefusal::Signature)
            }
            (
                SignatureAlgorithm::EcdsaSha256 | SignatureAlgorithm::EcdsaSha384,
                SubjectKey::P256(..) | SubjectKey::P384(_) | SubjectKey::Other,
            ) => Err(IssuanceRefusal::IssuerKey),
        }
    }
}

/// Two certificates are one when their DER bytes are.
impl PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        self.der == other.der
    }
}

impl Eq for Certificate {}

impl SignatureAlgorithm {
    fn of(algorithm: &AlgorithmIdentifierOwned) -> Self {
        match (algorithm.oid, &algorithm.parameters) {
            (ECDSA_SHA256, None) => Self::EcdsaSha256,
            (ECDSA_SHA384, None) => Self::EcdsaSha384,
            _ => Self::Other,
        }
    }
}

impl SubjectKey {
    /// The key of `spki`. An `id-ecPublicKey` whose parameters name another curve, or name none
    /// that decodes, is a key of another type.
    fn read(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<Self, PublicKeyFault> {
        if spki.algorithm.oid != EC_PUBLIC_KEY {
            return Ok(Self::Other);
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .map(|parameters| parameters.decode_as::<ObjectIdentifier>());
        let point = || {
            spki.subject_public_key
                .as_bytes()
                .ok_or(PublicKeyFault::Bits)
        };
        match curve {
            Some(Ok(SECP256R1)) => {
                let point = point()?;
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point)
                    .map_err(|_| PublicKeyFault::P256)?;
                Ok(Self::P256(key, point.to_vec()))
            }
            Some(Ok(SECP384R1)) => p384::ecdsa::VerifyingKey::from_sec1_bytes(point()?)
                .map(Self::P384)
                .map_err(|_| PublicKeyFault::P384),
            Some(Ok(_) | Err(_)) | None => Ok(Self::Other),
        }
    }
}

/// The extensions issuer trust reads.
struct Extensions {
    role: CertificateRole,
    authority_key_identifier: Option<KeyIdentifier>,
    subject_key_identifier: Option<KeyIdentifier>,
}

impl Extensions {
    /// The extensions of a certificate that has none.
    const NONE: Self = Self {
        role: CertificateRole::EndEntity,
        authority_key_identifier: None,
        subject_key_identifier: None,
    };

    fn read(extensions: &[x509_cert::ext::Extension]) -> Result<Self, CertificateError> {
        let repeated = extensions.iter().enumerate().find(|(position, extension)| {
            extensions
                .iter()
                .take(*position)
                .any(|earlier| earlier.extn_id == extension.extn_id)
        });
        if let Some((_, extension)) = repeated {
            return Err(CertificateError::ExtensionRepeated(extension.extn_id));
        }
        let value = |oid: ObjectIdentifier| {
            extensions
                .iter()
                .find(|extension| extension.extn_id == oid)
                .map(|extension| extension.extn_value.as_bytes())
        };
        let role = match value(BASIC_CONSTRAINTS) {
            None => CertificateRole::EndEntity,
            Some(bytes) => match BasicConstraints::from_der(bytes) {
                Ok(constraints) if constraints.ca => CertificateRole::Ca,
                Ok(_) => CertificateRole::EndEntity,
                Err(error) => return Err(CertificateError::BasicConstraints(error)),
            },
        };
        let authority_key_identifier = value(AUTHORITY_KEY_IDENTIFIER)
            .map(authority_key_identifier)
            .transpose()
            .map_err(CertificateError::AuthorityKeyIdentifier)?
            .flatten();
        let subject_key_identifier = value(SUBJECT_KEY_IDENTIFIER)
            .map(subject_key_identifier)
            .transpose()
            .map_err(CertificateError::SubjectKeyIdentifier)?;
        Ok(Self {
            role,
            authority_key_identifier,
            subject_key_identifier,
        })
    }
}

/// The keyIdentifier of the AuthorityKeyIdentifier extension `bytes`; `None` without one.
fn authority_key_identifier(bytes: &[u8]) -> Result<Option<KeyIdentifier>, KeyIdentifierFault> {
    let extension = AuthorityKeyIdentifier::from_der(bytes).map_err(KeyIdentifierFault::Der)?;
    extension
        .key_identifier
        .map(|key_identifier| KeyIdentifier::new(key_identifier.as_bytes()))
        .transpose()
        .map_err(KeyIdentifierFault::KeyIdentifier)
}

/// The keyIdentifier of the SubjectKeyIdentifier extension `bytes`: an OCTET STRING.
fn subject_key_identifier(bytes: &[u8]) -> Result<KeyIdentifier, KeyIdentifierFault> {
    let key_identifier = OctetString::from_der(bytes).map_err(KeyIdentifierFault::Der)?;
    KeyIdentifier::new(key_identifier.as_bytes()).map_err(KeyIdentifierFault::KeyIdentifier)
}

/// The `tbsCertificate` of the certificate `der`, as written: the bytes its signature covers.
fn tbs_bytes(der: &[u8]) -> Result<&[u8], der::Error> {
    let mut reader = SliceReader::new(der)?;
    let header = Header::decode(&mut reader)?;
    if header.tag != Tag::Sequence {
        return Err(header.tag.unexpected_error(Some(Tag::Sequence)));
    }
    reader.tlv_bytes()
}

/// `time`, the time `which` of the validity period, as a UTC time of the years 0000 to 9999.
fn time(time: Time, which: ValidityTime) -> Result<DateTime, CertificateError> {
    let seconds = i64::try_from(time.to_unix_duration().as_secs())
        .map_err(|_| CertificateError::Validity(which))?;
    DateTime::from_unix(seconds).ok_or(CertificateError::Validity(which))
}
