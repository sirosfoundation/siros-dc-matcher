//! The Document Signer certificate of `x5chain` and `issuer_key_set` (system rulebooks,
//! Section 6): an X.509 certificate with an uncompressed P-256 key.

use std::fmt;

use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, VerifyingKey};
use x509_cert::Certificate;

use crate::mdoc::P256Key;

/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` (RFC 5480).
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `ecdsa-with-SHA256` (RFC 5758).
const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// Why a certificate is not a Document Signer certificate of the systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateError {
    /// The bytes are not one DER X.509 certificate.
    Der,
    /// The key's algorithm is not `id-ecPublicKey` on `prime256v1`.
    Algorithm,
    /// The key is not an uncompressed point of P-256.
    Point,
}

impl fmt::Display for CertificateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Der => "not a DER X.509 certificate",
            Self::Algorithm => "the key is not id-ecPublicKey on prime256v1",
            Self::Point => "the key is not an uncompressed P-256 point",
        })
    }
}

impl std::error::Error for CertificateError {}

/// A parsed certificate with a P-256 key.
#[derive(Debug, Clone)]
pub struct P256Certificate {
    /// The DER bytes.
    pub der: Vec<u8>,
    /// The subject's key, the issuer key Q of the statement.
    pub key: P256Key,
    certificate: Certificate,
}

impl P256Certificate {
    /// Parses a DER certificate whose key is an uncompressed P-256 point.
    ///
    /// # Errors
    ///
    /// [`CertificateError`]: what the certificate breaks.
    pub fn parse(der: &[u8]) -> Result<Self, CertificateError> {
        let certificate = Certificate::from_der(der).map_err(|_| CertificateError::Der)?;
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        if spki.algorithm.oid != EC_PUBLIC_KEY || curve != Some(PRIME256V1) {
            return Err(CertificateError::Algorithm);
        }
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(CertificateError::Point)?;
        let key = point_key(point).ok_or(CertificateError::Point)?;
        Ok(Self {
            der: der.to_vec(),
            key,
            certificate,
        })
    }

    /// Whether `unix` lies in the validity period.
    pub fn valid_at(&self, unix: i64) -> bool {
        let validity = &self.certificate.tbs_certificate.validity;
        let seconds =
            |t: &x509_cert::time::Time| i64::try_from(t.to_unix_duration().as_secs()).ok();
        match (seconds(&validity.not_before), seconds(&validity.not_after)) {
            (Some(from), Some(until)) => from <= unix && unix <= until,
            _ => false,
        }
    }

    /// Whether the certificate is `anchor`, or `anchor` signed it with ECDSA and SHA-256.
    pub fn issued_by(&self, anchor: &Self) -> bool {
        if self.der == anchor.der {
            return true;
        }
        let tbs = &self.certificate.tbs_certificate;
        if tbs.issuer != anchor.certificate.tbs_certificate.subject
            || self.certificate.signature_algorithm.oid != ECDSA_SHA256
        {
            return false;
        }
        let (Ok(tbs_der), Some(signature)) = (tbs.to_der(), self.certificate.signature.as_bytes())
        else {
            return false;
        };
        let (Ok(key), Ok(signature)) = (
            VerifyingKey::from_sec1_bytes(&anchor.key.sec1()),
            DerSignature::from_bytes(signature),
        ) else {
            return false;
        };
        key.verify(&tbs_der, &signature).is_ok()
    }
}

/// The key of an uncompressed SEC 1 point on P-256.
fn point_key(point: &[u8]) -> Option<P256Key> {
    if point.len() != 65 || point.first() != Some(&0x04) {
        return None;
    }
    VerifyingKey::from_sec1_bytes(point).ok()?;
    Some(P256Key {
        x: point.get(1..33)?.try_into().ok()?,
        y: point.get(33..65)?.try_into().ok()?,
    })
}

/// Whether the certificate chains to one of `anchors` (DER): it is one, or a P-256 anchor
/// signed it with ECDSA and SHA-256. An anchor with another key type matches only itself.
pub fn chains_to(certificate: &P256Certificate, anchors: &[Vec<u8>]) -> bool {
    anchors.iter().any(|anchor| {
        *anchor == certificate.der
            || P256Certificate::parse(anchor).is_ok_and(|a| certificate.issued_by(&a))
    })
}
