//! An X.509 certificate (RFC 5280), as issuer trust reads it: its names, validity, key,
//! basicConstraints, AuthorityKeyIdentifier and signature.

use std::fmt;

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use p256::ecdsa::signature::Verifier;
use siros_codec::date::DateTime;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use crate::authority::KeyIdentifier;

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

/// A DER X.509 certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    algorithm: SignatureAlgorithm,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    not_before: DateTime,
    not_after: DateTime,
    key: SubjectKey,
    authority_key_identifier: Option<KeyIdentifier>,
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

/// Why bytes are no certificate issuer trust reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateError {
    /// The bytes are not one DER X.509 certificate.
    Der,
    /// `signatureAlgorithm` differs from the `signature` field of `tbsCertificate` (RFC 5280,
    /// Section 4.1.1.2).
    AlgorithmMismatch,
    /// The signature is not a BIT STRING of whole bytes.
    Signature,
    /// The issuer or subject name does not encode.
    Name,
    /// A time of the validity period lies outside 0000 to 9999.
    Validity,
    /// The subject's key is declared P-256 or P-384 and is no point of that curve.
    PublicKey,
    /// The certificate holds an extension twice (RFC 5280, Section 4.2).
    ExtensionRepeated,
    /// basicConstraints does not decode.
    BasicConstraints,
    /// The AuthorityKeyIdentifier does not decode, or its keyIdentifier is empty.
    AuthorityKeyIdentifier,
}

impl CertificateError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Der => "certificate_der",
            Self::AlgorithmMismatch => "certificate_algorithm_mismatch",
            Self::Signature => "certificate_signature",
            Self::Name => "certificate_name",
            Self::Validity => "certificate_validity",
            Self::PublicKey => "certificate_public_key",
            Self::ExtensionRepeated => "certificate_extension_repeated",
            Self::BasicConstraints => "certificate_basic_constraints",
            Self::AuthorityKeyIdentifier => "certificate_authority_key_identifier",
        }
    }
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for CertificateError {}

/// Why a certificate is not issued by another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IssuanceRefusal {
    /// The certificate names another issuer than the other's subject.
    IssuerName,
    /// The signature algorithm with the issuer's key is neither ECDSA P-256 with SHA-256 nor
    /// P-384 with SHA-384.
    Algorithm,
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
        let certificate =
            x509_cert::Certificate::from_der(der).map_err(|_| CertificateError::Der)?;
        let tbs_certificate = &certificate.tbs_certificate;
        if certificate.signature_algorithm != tbs_certificate.signature {
            return Err(CertificateError::AlgorithmMismatch);
        }
        let extensions = Extensions::read(tbs_certificate.extensions.as_deref().unwrap_or(&[]))?;
        let name = |name: &x509_cert::name::Name| name.to_der().map_err(|_| CertificateError::Name);
        Ok(Self {
            der: der.to_vec(),
            tbs: tbs_certificate
                .to_der()
                .map_err(|_| CertificateError::Der)?,
            signature: certificate
                .signature
                .as_bytes()
                .ok_or(CertificateError::Signature)?
                .to_vec(),
            algorithm: SignatureAlgorithm::of(&certificate.signature_algorithm),
            issuer: name(&tbs_certificate.issuer)?,
            subject: name(&tbs_certificate.subject)?,
            not_before: time(tbs_certificate.validity.not_before)?,
            not_after: time(tbs_certificate.validity.not_after)?,
            key: SubjectKey::read(&tbs_certificate.subject_public_key_info)?,
            authority_key_identifier: extensions.authority_key_identifier,
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
    pub fn valid_at(&self, time: DateTime) -> bool {
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
    pub fn issued_by(&self, issuer: &Self) -> Result<(), IssuanceRefusal> {
        if !self.names_as_issuer(issuer) {
            return Err(IssuanceRefusal::IssuerName);
        }
        let verified = match (self.algorithm, &issuer.key) {
            (SignatureAlgorithm::EcdsaSha256, SubjectKey::P256(key, _)) => {
                p256::ecdsa::DerSignature::from_bytes(&self.signature)
                    .is_ok_and(|signature| key.verify(&self.tbs, &signature).is_ok())
            }
            (SignatureAlgorithm::EcdsaSha384, SubjectKey::P384(key)) => {
                p384::ecdsa::DerSignature::from_bytes(&self.signature)
                    .is_ok_and(|signature| key.verify(&self.tbs, &signature).is_ok())
            }
            _ => return Err(IssuanceRefusal::Algorithm),
        };
        if verified {
            Ok(())
        } else {
            Err(IssuanceRefusal::Signature)
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
    fn read(spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> Result<Self, CertificateError> {
        if spki.algorithm.oid != EC_PUBLIC_KEY {
            return Ok(Self::Other);
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
        let point = spki.subject_public_key.as_bytes();
        match curve {
            Some(SECP256R1) => point
                .and_then(|point| {
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).ok()?;
                    Some(Self::P256(key, point.to_vec()))
                })
                .ok_or(CertificateError::PublicKey),
            Some(SECP384R1) => point
                .and_then(|point| p384::ecdsa::VerifyingKey::from_sec1_bytes(point).ok())
                .map(Self::P384)
                .ok_or(CertificateError::PublicKey),
            _ => Ok(Self::Other),
        }
    }
}

/// The extensions issuer trust reads.
struct Extensions {
    role: CertificateRole,
    authority_key_identifier: Option<KeyIdentifier>,
}

impl Extensions {
    fn read(extensions: &[x509_cert::ext::Extension]) -> Result<Self, CertificateError> {
        let repeated = extensions.iter().enumerate().any(|(position, extension)| {
            extensions
                .iter()
                .take(position)
                .any(|earlier| earlier.extn_id == extension.extn_id)
        });
        if repeated {
            return Err(CertificateError::ExtensionRepeated);
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
                Err(_) => return Err(CertificateError::BasicConstraints),
            },
        };
        let authority_key_identifier = value(AUTHORITY_KEY_IDENTIFIER)
            .map(|bytes| {
                let extension = AuthorityKeyIdentifier::from_der(bytes)
                    .map_err(|_| CertificateError::AuthorityKeyIdentifier)?;
                extension
                    .key_identifier
                    .map(|key_identifier| KeyIdentifier::new(key_identifier.as_bytes()))
                    .transpose()
                    .map_err(|_| CertificateError::AuthorityKeyIdentifier)
            })
            .transpose()?
            .flatten();
        Ok(Self {
            role,
            authority_key_identifier,
        })
    }
}

/// `time` as a UTC time.
fn time(time: Time) -> Result<DateTime, CertificateError> {
    i64::try_from(time.to_unix_duration().as_secs())
        .ok()
        .and_then(DateTime::from_unix)
        .ok_or(CertificateError::Validity)
}
