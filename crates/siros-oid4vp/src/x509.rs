//! The certificate chain of an `x5c` Header Parameter (RFC 7515, Section 4.1.6) and what the
//! wallet reads from its leaf: the P-256 key, the dNSName SANs (RFC 5280, Section 4.2.1.6) and
//! the semantics identifier of its subject (ETSI EN 319 412-1, Clauses 5.1.3 and 5.1.4).
//!
//! The chain is validated by the host's trust evaluation; the core binds the leaf.

use der::asn1::{ObjectIdentifier, PrintableStringRef, Utf8StringRef};
use der::{Any, Decode};
use p256::PublicKey;
use serde_json::Value;
use siros_codec::base64;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::Certificate;

use crate::intake::IntakeError;
use crate::verified::AccessCertificate;

/// `id-ecPublicKey` (RFC 5480).
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1` (RFC 5480).
const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// `id-at-organizationIdentifier` (Recommendation ITU-T X.520).
const ORGANIZATION_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.97");
/// `id-at-serialNumber` (Recommendation ITU-T X.520).
const SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

/// The legal person identity type references of ETSI EN 319 412-1, LEG-5.1.4-03, and those
/// ETSI TS 119 475, Table 2 adds.
const LEGAL_TYPES: [&str; 6] = ["VAT", "NTR", "PSD", "LEI", "EOR", "EXC"];
/// The natural person identity type references of ETSI EN 319 412-1, NAT-5.1.3-03.
const NATURAL_TYPES: [&str; 5] = ["PAS", "IDC", "PNO", "TAX", "TIN"];

/// An `x5c` chain whose leaf has a P-256 key.
#[derive(Debug, Clone)]
pub(crate) struct Chain {
    der: Vec<Vec<u8>>,
    key: PublicKey,
    dns_names: Vec<String>,
    semantic_identifier: Option<String>,
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
        let semantic_identifier = semantic_identifier(&tbs.subject);
        Ok(Self {
            der,
            key,
            dns_names,
            semantic_identifier,
        })
    }

    /// The leaf as the Wallet-Relying Party's access certificate.
    pub(crate) fn access_certificate(&self) -> AccessCertificate {
        AccessCertificate {
            der: self.leaf().to_vec(),
            semantic_identifier: self.semantic_identifier.clone(),
        }
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

/// The semantics identifier of `subject` (ETSI TS 119 475, Clauses 5.1.3 and 5.1.5).
///
/// "GEN-5.1.3-01: The organizationIdentifier shall follow the semantics defined in ETSI
/// EN 319 412-1 [1], clause 5.1.4." "GEN-5.1.5-01: The serialNumber with shall follow the semantics
/// defined in ETSI EN 319 412-1 [1], clause 5.1.3." Both clauses of EN 319 412-1 (LEG-5.1.4-02,
/// NAT-5.1.3-02) give the value "the following structure in the presented order: 3 character
/// [...] identity type reference; 2 character ISO 3166-1 country code; hyphen-minus "-" [...];
/// and identifier", where the type reference may instead be two characters of a local scheme
/// followed by ":" (LEG-5.1.4-03 point 5, NAT-5.1.3-03 point 6).
///
/// A legal person's certificate carries an `organizationIdentifier`, a natural person's a
/// `serialNumber`. The value is the one `organizationIdentifier` of that structure; without an
/// `organizationIdentifier`, the one `serialNumber` of that structure. `None` for any other
/// subject.
fn semantic_identifier(subject: &Name) -> Option<String> {
    let values = |oid: ObjectIdentifier| -> Vec<&Any> {
        subject
            .0
            .iter()
            .flat_map(|rdn| rdn.0.iter())
            .filter(|attribute| attribute.oid == oid)
            .map(|attribute| &attribute.value)
            .collect()
    };
    let (found, types): (Vec<&Any>, &[&str]) = match values(ORGANIZATION_IDENTIFIER) {
        organization if !organization.is_empty() => (organization, &LEGAL_TYPES),
        _ => (values(SERIAL_NUMBER), &NATURAL_TYPES),
    };
    let [value] = found.as_slice() else {
        return None;
    };
    let text = directory_string(value)?;
    structured(&text, types).then_some(text)
}

/// The text of a `DirectoryString` (or `PrintableString`) value: UTF-8 or printable.
fn directory_string(value: &Any) -> Option<String> {
    if let Ok(text) = value.decode_as::<Utf8StringRef<'_>>() {
        return Some(text.as_str().to_owned());
    }
    value
        .decode_as::<PrintableStringRef<'_>>()
        .ok()
        .map(|text| text.as_str().to_owned())
}

/// Whether `text` is a type reference of `types` or two characters and ":", two uppercase
/// letters of a country code, "-" and a non-empty identifier.
fn structured(text: &str, types: &[&str]) -> bool {
    let rest = match text.get(..3) {
        Some(head) if types.contains(&head) => text.get(3..),
        Some(head) if head.ends_with(':') && head.is_ascii() => text.get(3..),
        _ => None,
    };
    let Some(rest) = rest else {
        return false;
    };
    let country = rest
        .get(..2)
        .filter(|c| c.bytes().all(|b| b.is_ascii_uppercase()));
    country.is_some() && rest.get(2..3) == Some("-") && rest.len() > 3
}
