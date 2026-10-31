//! The v1 credential blob, which the FFI's `SirosBlobBuilder` writes and its in-process match
//! reads. Its writer and its reader update independently, so the format survives version skew
//! both ways:
//!
//! - **Everything is versioned.** [`CredentialDatabase::version`] is checked
//!   before anything else is trusted.
//! - **Unknown fields are ignored, never rejected.** A newer writer must not
//!   break an older reader, which does not act on what it cannot see.
//! - **Text keys, not integer keys.** Integer keys would be smaller, but the
//!   blob's size is dominated by claim values and icons, and being able to
//!   `cbor-diag` a blob recovered from a device is worth more than the bytes.
//!
//! # Why claim values are in here
//!
//! The match evaluates a verifier's DCQL query, its `values` filters included.

use serde::{Deserialize, Serialize};
use siros_dcql::{CredentialFormat, CredentialRef};

use crate::profile::MatchProfile;

/// Format version of the blob.
///
/// Bumped only for a change an older matcher cannot safely ignore. Adding an
/// optional field is not such a change — that is what
/// `#[serde(default)]` throughout this module is for.
pub const VERSION: u32 = 1;

/// Everything a wallet registers: what it holds, and the rules for offering it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialDatabase {
    /// Format version. See [`VERSION`].
    pub version: u32,
    /// The rules this wallet wants applied. See [`MatchProfile`].
    pub profile: MatchProfile,
    /// Credentials available for matching.
    pub credentials: Vec<Credential>,
    /// Icon bytes, concatenated and referenced by [`IconRef`].
    ///
    /// One blob rather than a field per credential: wallets routinely hold
    /// several credentials from one issuer, and storing that issuer's logo once
    /// keeps the registered payload proportional to issuers rather than to
    /// credentials.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<u8>,
}

/// One credential the wallet holds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    /// Wallet-side identifier, returned when the user selects this entry.
    ///
    /// Opaque to the matcher. It must be meaningful to the wallet, and must
    /// not be a value the wallet would mind the platform storing.
    pub id: CredentialRef,
    /// Storage format, e.g. `mso_mdoc` or `dc+sd-jwt`.
    ///
    /// The format a *verifier asks for* is a separate thing, mapped onto this
    /// by the profile — see [`crate::profile::FormatRule`].
    pub format: CredentialFormat,
    /// ISO mdoc docType, when this is an mdoc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    /// SD-JWT VC type, when this is an SD-JWT VC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    /// Primary line shown in the picker.
    pub title: String,
    /// Secondary line, typically the issuer.
    #[serde(default)]
    pub subtitle: String,
    /// Where this credential's icon lives in [`CredentialDatabase::icons`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<IconRef>,
    /// Claims available for matching and display.
    #[serde(default)]
    pub claims: Vec<Claim>,
}

/// A slice of [`CredentialDatabase::icons`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IconRef {
    /// Byte offset into the icon blob.
    pub start: u32,
    /// Length in bytes.
    pub len: u32,
}

/// One claim, as both a matchable value and a displayable one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    /// DCQL path to this claim.
    ///
    /// For ISO mdoc: `[namespace, element_identifier]`. For JSON-based
    /// credentials: the path components.
    ///
    /// Note the shape — a *list*, not a dotted string. ISO mdoc namespaces
    /// contain dots themselves (`org.iso.18013.5.1`), so flattening and
    /// re-splitting loses the boundary and silently mis-parses every ISO
    /// namespace.
    pub path: Vec<String>,
    /// The value, for DCQL `values` filtering.
    ///
    /// A string rather than an arbitrary CBOR item: DCQL compares claim values
    /// to JSON literals from the query, so the comparison happens in string
    /// space either way, and keeping it flat avoids a second value model that
    /// would have to agree with `serde_json`'s in every edge case.
    #[serde(default)]
    pub value: String,
    /// Human-readable label for the picker.
    #[serde(default)]
    pub display: String,
    /// Human-readable value for the picker, when it differs from [`Self::value`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_value: Option<String>,
}

/// Why a blob could not be read.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// The bytes end inside an item.
    #[error("credential blob ends inside an item")]
    Truncated,
    /// The bytes are no CBOR at this offset.
    #[error("credential blob is no CBOR at byte {0}")]
    Syntax(usize),
    /// The CBOR is not shaped like a database: where, when the reader knows, and what it found.
    #[error(
        "credential blob is no database{at}: {found}",
        at = .0.map_or_else(String::new, |offset| format!(" at byte {offset}")),
        found = .1
    )]
    Shape(Option<usize>, String),
    /// Items nest deeper than the reader allows.
    #[error("credential blob nests too deeply")]
    TooDeep,
    /// The blob's version is one this matcher does not understand.
    ///
    /// Carries the version so a diagnostic can say *which*, which is the
    /// difference between "the wallet is newer than the matcher" and "the blob
    /// is corrupt".
    #[error("credential blob version {0} is newer than this matcher")]
    UnsupportedVersion(u32),
}

impl CredentialDatabase {
    /// An empty database carrying the given profile.
    pub fn new(profile: MatchProfile) -> Self {
        Self {
            version: VERSION,
            profile,
            credentials: Vec::new(),
            icons: Vec::new(),
        }
    }

    /// Serialise to CBOR.
    ///
    /// # Errors
    ///
    /// Only if the writer fails, which for an in-memory buffer it does not.
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut out = Vec::new();
        ciborium::into_writer(self, &mut out)?;
        Ok(out)
    }

    /// Parse a blob produced by [`Self::to_cbor`].
    ///
    /// # Errors
    ///
    /// [`DecodeError`]: bytes that are no database, or a blob from a future wallet
    /// ([`DecodeError::UnsupportedVersion`]).
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let db: Self = ciborium::from_reader(bytes).map_err(|error| match error {
            // The reader is the byte slice, whose only failure is its end.
            ciborium::de::Error::Io(_) => DecodeError::Truncated,
            ciborium::de::Error::Syntax(offset) => DecodeError::Syntax(offset),
            ciborium::de::Error::Semantic(offset, found) => DecodeError::Shape(offset, found),
            ciborium::de::Error::RecursionLimitExceeded => DecodeError::TooDeep,
        })?;
        if db.version > VERSION {
            return Err(DecodeError::UnsupportedVersion(db.version));
        }
        Ok(db)
    }

    /// The icon bytes for a credential, if it has one and the reference is
    /// within bounds.
    ///
    /// `None` for a reference outside the icon buffer: it costs that credential its picture.
    pub fn icon_bytes(&self, credential: &Credential) -> Option<&[u8]> {
        let r = credential.icon?;
        let start = r.start as usize;
        let end = start.checked_add(r.len as usize)?;
        self.icons.get(start..end)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::profile::{FormatRule, MetaRule, Op, ZKP_REQ_FORMAT};

    fn sample() -> CredentialDatabase {
        let mut profile = MatchProfile::default();
        profile.formats.push(FormatRule {
            query_format: ZKP_REQ_FORMAT.into(),
            stored_formats: vec!["mso_mdoc".into()],
        });
        profile.meta_rules.push(MetaRule {
            meta_key: "doctype_value".into(),
            field: Some("doctype".into()),
            op: Op::Eq,
        });

        CredentialDatabase {
            version: VERSION,
            profile,
            credentials: vec![Credential {
                id: "cred-1".into(),
                format: "mso_mdoc".into(),
                doctype: Some("org.iso.18013.5.1.mDL".into()),
                vct: None,
                title: "Driving Licence".into(),
                subtitle: "Transportstyrelsen".into(),
                icon: Some(IconRef { start: 0, len: 4 }),
                claims: vec![Claim {
                    path: vec!["org.iso.18013.5.1".into(), "family_name".into()],
                    value: "Johansson".into(),
                    display: "Family name".into(),
                    display_value: None,
                }],
            }],
            icons: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }
    }

    #[test]
    fn round_trips() {
        let db = sample();
        let bytes = db.to_cbor().unwrap();
        assert_eq!(CredentialDatabase::from_cbor(&bytes).unwrap(), db);
    }

    /// The mdoc namespace must survive as its own path element. Flattening to
    /// a dotted string and splitting it back is how `org.iso.18013.5.1`
    /// silently becomes namespace `org`.
    #[test]
    fn dotted_mdoc_namespace_survives_as_one_path_element() {
        let bytes = sample().to_cbor().unwrap();
        let db = CredentialDatabase::from_cbor(&bytes).unwrap();
        let path = &db.credentials[0].claims[0].path;
        assert_eq!(path.len(), 2);
        assert_eq!(path[0], "org.iso.18013.5.1");
        assert_eq!(path[1], "family_name");
    }

    /// A newer wallet's blob must be reported as such, not as corruption —
    /// the two call for completely different responses.
    #[test]
    fn future_version_is_distinguishable_from_corruption() {
        let mut db = sample();
        db.version = VERSION + 7;
        let bytes = db.to_cbor().unwrap();
        assert_eq!(
            CredentialDatabase::from_cbor(&bytes),
            Err(DecodeError::UnsupportedVersion(VERSION + 7))
        );
        assert!(matches!(
            CredentialDatabase::from_cbor(b"\xff\xff not cbor"),
            Err(DecodeError::Shape(..))
        ));
    }

    /// Garbage in must not panic: this runs where a trap shows the user
    /// nothing and says nothing.
    #[test]
    fn malformed_input_never_panics() {
        for bytes in [
            &b""[..],
            b"\x00",
            b"\xff\xff\xff",
            b"not cbor at all",
            &[0xA1; 64],
        ] {
            assert!(CredentialDatabase::from_cbor(bytes).is_err());
        }
    }

    #[test]
    fn icon_lookup_is_bounds_checked() {
        let db = sample();
        assert_eq!(
            db.icon_bytes(&db.credentials[0]),
            Some(&[0xDE, 0xAD, 0xBE, 0xEF][..])
        );

        let mut cred = db.credentials[0].clone();
        cred.icon = Some(IconRef { start: 2, len: 999 });
        assert_eq!(db.icon_bytes(&cred), None);
        cred.icon = Some(IconRef {
            start: u32::MAX,
            len: u32::MAX,
        });
        assert_eq!(db.icon_bytes(&cred), None);
    }

    /// An older matcher meeting a newer wallet's extra fields must ignore
    /// them, not refuse the whole blob.
    #[test]
    fn unknown_fields_are_ignored() {
        let json = serde_json::json!({
            "version": 1,
            "profile": {"formats": [], "meta_rules": [], "protocols": [],
                        "capabilities": {}, "unknown_format": "reject",
                        "something_from_the_future": 42},
            "credentials": [],
            "a_whole_new_section": ["surprise"],
        });
        let mut bytes = Vec::new();
        ciborium::into_writer(&json, &mut bytes).unwrap();
        assert!(CredentialDatabase::from_cbor(&bytes).is_ok());
    }
}
