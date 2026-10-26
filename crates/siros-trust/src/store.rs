//! The trust store the host provisions (TR1, TR4): for each authority a Verifier may name, the
//! certificates an issuer chain validates up to.

use std::fmt;

use serde_json::{Map, Value};
use siros_codec::base64;
use siros_dcql::{AuthorityType, AuthorityValue};

use crate::authority::{StoreAuthority, StoreType};
use crate::certificate::{Certificate, CertificateError};
use crate::position::{CertificateIndex, EntryIndex};

/// The trust store: its entries, each authority once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustStore {
    entries: Vec<StoreEntry>,
}

/// An entry of the trust store: an authority and its certificates, at least one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreEntry {
    authority: StoreAuthority,
    certificates: Vec<Certificate>,
}

/// Why a record is no trust store (TR1).
#[derive(Debug)]
pub enum StoreError {
    /// The record is not JSON.
    Json(serde_json::Error),
    /// The record is not a JSON array.
    NotArray,
    /// An entry breaks a rule.
    Entry {
        /// The entry's position.
        entry: EntryIndex,
        /// The rule.
        error: EntryError,
    },
    /// An entry repeats the `type` and `value` of an earlier one.
    Repeated(EntryIndex),
}

/// Why an entry of a trust store record is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryError {
    /// The entry is not a JSON object.
    NotObject,
    /// The entry has a member other than `type`, `value` and `certificates`.
    UnknownMember,
    /// `type` is missing or not a string.
    Type,
    /// `type` is neither `etsi_tl` nor `openid_federation`.
    UnknownType,
    /// `value` is missing or not a string.
    Value,
    /// `certificates` is missing, not an array, or empty.
    Certificates,
    /// A certificate is not a string of base64 with padding (the `x5c` encoding, RFC 7515,
    /// Section 4.1.6).
    Encoding(CertificateIndex),
    /// A certificate does not parse.
    Certificate {
        /// Its position in `certificates`.
        certificate: CertificateIndex,
        /// Why.
        error: CertificateError,
    },
}

impl StoreError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "trust_store_json",
            Self::NotArray => "trust_store_not_array",
            Self::Entry { error, .. } => error.code(),
            Self::Repeated(_) => "trust_store_entry_repeated",
        }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "{}: {e}", self.code()),
            Self::NotArray => f.write_str(self.code()),
            Self::Entry { entry, .. } | Self::Repeated(entry) => {
                write!(f, "{} at entry {}", self.code(), entry.value())
            }
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Entry { error, .. } => Some(error),
            Self::NotArray | Self::Repeated(_) => None,
        }
    }
}

impl EntryError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotObject => "trust_store_entry_not_object",
            Self::UnknownMember => "trust_store_entry_member_unknown",
            Self::Type => "trust_store_entry_type",
            Self::UnknownType => "trust_store_entry_type_unknown",
            Self::Value => "trust_store_entry_value",
            Self::Certificates => "trust_store_entry_certificates",
            Self::Encoding(_) => "trust_store_certificate_encoding",
            Self::Certificate { error, .. } => error.code(),
        }
    }
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EntryError {}

impl TrustStore {
    /// The trust store of the JSON record `record`: an array of entries `{type, value,
    /// certificates}`, `type` `etsi_tl` or `openid_federation`, `value` the authority's value as
    /// a Verifier sends it, and `certificates` a non-empty array of DER certificates, each in
    /// base64 with padding. No two entries share a `type` and a `value`.
    ///
    /// # Errors
    ///
    /// [`StoreError`]: the first rule the record breaks.
    pub fn parse(record: &str) -> Result<Self, StoreError> {
        let record: Value = serde_json::from_str(record).map_err(StoreError::Json)?;
        let entries = record.as_array().ok_or(StoreError::NotArray)?;
        let mut parsed: Vec<StoreEntry> = Vec::with_capacity(entries.len());
        for (position, entry) in entries.iter().enumerate() {
            let entry_index = EntryIndex::new(position);
            let entry = StoreEntry::parse(entry).map_err(|error| StoreError::Entry {
                entry: entry_index,
                error,
            })?;
            if parsed
                .iter()
                .any(|earlier| earlier.authority == entry.authority)
            {
                return Err(StoreError::Repeated(entry_index));
            }
            parsed.push(entry);
        }
        Ok(Self { entries: parsed })
    }

    /// The entries, in the record's order.
    #[must_use]
    pub fn entries(&self) -> &[StoreEntry] {
        &self.entries
    }

    /// The entry of `authority`.
    #[must_use]
    pub fn entry(&self, authority: &StoreAuthority) -> Option<&StoreEntry> {
        self.entries
            .iter()
            .find(|entry| entry.authority == *authority)
    }
}

impl StoreEntry {
    fn parse(entry: &Value) -> Result<Self, EntryError> {
        let entry = entry.as_object().ok_or(EntryError::NotObject)?;
        if entry
            .keys()
            .any(|name| !matches!(name.as_str(), "type" | "value" | "certificates"))
        {
            return Err(EntryError::UnknownMember);
        }
        let kind = text(entry, "type").ok_or(EntryError::Type)?;
        let kind = StoreType::of(&AuthorityType::new(kind)).ok_or(EntryError::UnknownType)?;
        let value = text(entry, "value").ok_or(EntryError::Value)?;
        let certificates = match entry.get("certificates") {
            Some(Value::Array(certificates)) if !certificates.is_empty() => certificates,
            _ => return Err(EntryError::Certificates),
        };
        Ok(Self {
            authority: StoreAuthority::new(kind, AuthorityValue::new(value)),
            certificates: certificates
                .iter()
                .enumerate()
                .map(|(position, certificate)| {
                    certificate_of(certificate, CertificateIndex::new(position))
                })
                .collect::<Result<_, _>>()?,
        })
    }

    /// The authority.
    #[must_use]
    pub fn authority(&self) -> &StoreAuthority {
        &self.authority
    }

    /// The certificates, at least one, in the record's order.
    #[must_use]
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }
}

/// The string member `name` of `entry`.
fn text<'e>(entry: &'e Map<String, Value>, name: &str) -> Option<&'e str> {
    entry.get(name).and_then(Value::as_str)
}

/// The certificate at `position` of an entry's `certificates`: base64 with padding of a DER
/// certificate.
fn certificate_of(value: &Value, position: CertificateIndex) -> Result<Certificate, EntryError> {
    let der = value
        .as_str()
        .and_then(base64::decode)
        .ok_or(EntryError::Encoding(position))?;
    Certificate::parse(&der).map_err(|error| EntryError::Certificate {
        certificate: position,
        error,
    })
}
