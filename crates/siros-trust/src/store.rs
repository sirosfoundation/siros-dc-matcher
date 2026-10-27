//! The trust store the host provisions (TR1, TR4): for each authority a Verifier may name, the
//! certificates to which an issuer chain has a path.

use std::fmt;

use siros_codec::json::{Json, JsonTextError};
use siros_codec::{base64, Base64Error};
use siros_dcql::{AuthorityType, AuthorityValue};

use crate::authority::{AuthorityKind, StoreAuthority};
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The record is not JSON.
    Json(JsonTextError),
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

/// What breaks the rule of a member of a trust store entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberFault {
    /// It is absent.
    Absent,
    /// It has another JSON type than its rule gives it.
    WrongType,
    /// It is an empty array.
    Empty,
}

/// Why an entry of a trust store record is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryError {
    /// The entry is not a JSON object.
    NotObject,
    /// The entry has this member, other than `type`, `value` and `certificates`.
    UnknownMember(String),
    /// The entry names this member twice.
    RepeatedMember(String),
    /// `type` is absent or not a string.
    Type(MemberFault),
    /// `type` names this type, other than `etsi_tl` and `openid_federation`.
    UnknownType(AuthorityType),
    /// `value` is absent or not a string.
    Value(MemberFault),
    /// `certificates` is absent, not an array, or empty.
    Certificates(MemberFault),
    /// A certificate is not a string.
    CertificateNotString(CertificateIndex),
    /// A certificate is not base64 with padding (the `x5c` encoding, RFC 7515, Section 4.1.6).
    Encoding {
        /// Its position in `certificates`.
        certificate: CertificateIndex,
        /// Why.
        error: Base64Error,
    },
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
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject => "trust_store_entry_not_object",
            Self::UnknownMember(_) => "trust_store_entry_member_unknown",
            Self::RepeatedMember(_) => "trust_store_entry_member_repeated",
            Self::Type(_) => "trust_store_entry_type",
            Self::UnknownType(_) => "trust_store_entry_type_unknown",
            Self::Value(_) => "trust_store_entry_value",
            Self::Certificates(_) => "trust_store_entry_certificates",
            Self::CertificateNotString(_) => "trust_store_certificate_not_string",
            Self::Encoding { .. } => "trust_store_certificate_encoding",
            Self::Certificate { error, .. } => error.code(),
        }
    }
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for EntryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding { error, .. } => Some(error),
            Self::Certificate { error, .. } => Some(error),
            Self::NotObject
            | Self::UnknownMember(_)
            | Self::RepeatedMember(_)
            | Self::Type(_)
            | Self::UnknownType(_)
            | Self::Value(_)
            | Self::Certificates(_)
            | Self::CertificateNotString(_) => None,
        }
    }
}

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
        let Json::Array(entries) = Json::parse(record.as_bytes()).map_err(StoreError::Json)? else {
            return Err(StoreError::NotArray);
        };
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
    fn parse(entry: &Json) -> Result<Self, EntryError> {
        let Json::Object(members) = entry else {
            return Err(EntryError::NotObject);
        };
        if let Some((name, _)) = members
            .iter()
            .find(|(name, _)| !matches!(name.as_str(), "type" | "value" | "certificates"))
        {
            return Err(EntryError::UnknownMember(name.clone()));
        }
        if let Some(name) = entry.repeated_member() {
            return Err(EntryError::RepeatedMember(name.to_owned()));
        }
        let kind = AuthorityType::new(text(entry, "type").map_err(EntryError::Type)?);
        let kind = match AuthorityKind::of(&kind) {
            Some(AuthorityKind::Store(store)) => store,
            Some(AuthorityKind::Aki) | None => return Err(EntryError::UnknownType(kind)),
        };
        let value = text(entry, "value").map_err(EntryError::Value)?;
        let certificates = match entry.member("certificates") {
            None => return Err(EntryError::Certificates(MemberFault::Absent)),
            Some(Json::Array(certificates)) if certificates.is_empty() => {
                return Err(EntryError::Certificates(MemberFault::Empty))
            }
            Some(Json::Array(certificates)) => certificates,
            Some(_) => return Err(EntryError::Certificates(MemberFault::WrongType)),
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
fn text<'e>(entry: &'e Json, name: &str) -> Result<&'e str, MemberFault> {
    match entry.member(name) {
        None => Err(MemberFault::Absent),
        Some(Json::String(text)) => Ok(text),
        Some(_) => Err(MemberFault::WrongType),
    }
}

/// The certificate at `position` of an entry's `certificates`: base64 with padding of a DER
/// certificate.
fn certificate_of(value: &Json, position: CertificateIndex) -> Result<Certificate, EntryError> {
    let Json::String(text) = value else {
        return Err(EntryError::CertificateNotString(position));
    };
    let der = base64::decode(text).map_err(|error| EntryError::Encoding {
        certificate: position,
        error,
    })?;
    Certificate::parse(&der).map_err(|error| EntryError::Certificate {
        certificate: position,
        error,
    })
}
