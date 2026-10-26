//! The certificate chain of an `x5c` Header Parameter (RFC 7515, Section 4.1.6) and what the
//! wallet reads from its leaf: the P-256 key and the dNSName SANs (RFC 5280, Section 4.2.1.6).
//!
//! The chain is validated by the host's trust evaluation; the core binds the leaf.

use der::asn1::ObjectIdentifier;
use der::Decode;
use p256::PublicKey;
use serde_json::Value;
use siros_codec::base64;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::Certificate;

use crate::intake::IntakeError;

/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` (RFC 5480).
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// An `x5c` chain whose leaf has a P-256 key.
#[derive(Debug, Clone)]
pub(crate) struct Chain {
    der: Vec<Vec<u8>>,
    key: PublicKey,
    dns_names: Vec<String>,
}

impl Chain {
    /// The chain of the Header Parameter value `x5c`: a non-empty array of base64 DER
    /// certificates, leaf first.
    pub(crate) fn parse(x5c: Option<&Value>) -> Result<Self, IntakeError> {
        let der = x5c
            .and_then(Value::as_array)
            .filter(|chain| !chain.is_empty())
            .ok_or(IntakeError::CertificateChainInvalid)?
            .iter()
            .map(|c| c.as_str().and_then(base64::decode))
            .collect::<Option<Vec<_>>>()
            .ok_or(IntakeError::CertificateChainInvalid)?;
        let leaf = der
            .first()
            .and_then(|leaf| Certificate::from_der(leaf).ok())
            .ok_or(IntakeError::CertificateChainInvalid)?;
        let tbs = &leaf.tbs_certificate;
        let spki = &tbs.subject_public_key_info;
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        if spki.algorithm.oid != EC_PUBLIC_KEY || curve != Some(PRIME256V1) {
            return Err(IntakeError::CertificateChainInvalid);
        }
        let key = spki
            .subject_public_key
            .as_bytes()
            .and_then(|point| PublicKey::from_sec1_bytes(point).ok())
            .ok_or(IntakeError::CertificateChainInvalid)?;
        let dns_names = match tbs.get::<SubjectAltName>() {
            Ok(Some((_, san))) => san
                .0
                .iter()
                .filter_map(|name| match name {
                    GeneralName::DnsName(dns) => Some(dns.as_str().to_owned()),
                    _ => None,
                })
                .collect(),
            Ok(None) => Vec::new(),
            Err(_) => return Err(IntakeError::CertificateChainInvalid),
        };
        Ok(Self {
            der,
            key,
            dns_names,
        })
    }

    /// The leaf certificate's key.
    pub(crate) fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The leaf certificate, DER.
    pub(crate) fn leaf(&self) -> &[u8] {
        self.der.first().map(Vec::as_slice).unwrap_or_default()
    }

    /// Whether a dNSName SAN of the leaf is `name`, in ASCII case-insensitive comparison
    /// (RFC 4343).
    pub(crate) fn names_dns(&self, name: &str) -> bool {
        self.dns_names
            .iter()
            .any(|dns| dns.eq_ignore_ascii_case(name))
    }

    /// The chain, DER, leaf first.
    pub(crate) fn into_der(self) -> Vec<Vec<u8>> {
        self.der
    }
}
