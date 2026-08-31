//! Kotlin and Swift access to the credential blob and the matching engine.
//!
//! Two callers need this. The Kotlin SDK builds the blob it registers, and
//! matches again after the user has selected an entry. iOS has no WASM matcher
//! concept at all — when its OS-level Digital Credentials API integration
//! lands, matching happens in-process, and this is what it will call.
//!
//! # Why the types are mirrored rather than shared
//!
//! The natural thing would be to put `#[derive(uniffi::Record)]` on
//! [`siros_dc_matcher_core`]'s own types. It is not done, because UniFFI does
//! not build for `wasm32-wasip1` and `core` is on the matcher's critical path.
//! Deriving there would drag UniFFI into the binary that ships inside the
//! picker. Mirroring a handful of records here is the cheaper half of that
//! trade, and [`SirosBlobBuilder`] keeps the mirrored surface small by owning
//! the profile itself.

#![deny(missing_docs)]
#![deny(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use siros_dc_matcher_core::db::{Claim, Credential, CredentialDatabase, IconRef};
use siros_dc_matcher_core::profile::{Capability, MatchProfile, ZK_CAPABILITY};

pub mod matching;

uniffi::setup_scaffolding!();

/// Why a blob could not be built.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum BlobError {
    /// The credential set could not be encoded.
    #[error("could not encode the credential blob: {reason}")]
    Encoding {
        /// What went wrong.
        reason: String,
    },
    /// A credential referred to an icon that was never added.
    #[error("credential {credential_id} refers to unknown icon {icon_id}")]
    UnknownIcon {
        /// The credential holding the dangling reference.
        credential_id: String,
        /// The icon it asked for.
        icon_id: String,
    },
}

/// One claim, as the wallet knows it.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiClaim {
    /// DCQL path. For ISO mdoc this is `[namespace, element_identifier]`.
    ///
    /// A list, not a dotted string: ISO mdoc namespaces contain dots
    /// themselves (`org.iso.18013.5.1`), so flattening and re-splitting
    /// silently mis-parses every one of them.
    pub path: Vec<String>,
    /// The value, used for DCQL `values` filtering.
    pub value: String,
    /// Human-readable label.
    pub display: String,
    /// Human-readable value, when it differs from the `value` field.
    pub display_value: Option<String>,
}

/// One credential the wallet holds.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiCredential {
    /// Wallet-side identifier, returned when the user selects this entry.
    pub id: String,
    /// Storage format, e.g. `mso_mdoc` or `dc+sd-jwt`.
    pub format: String,
    /// ISO mdoc docType, when this is an mdoc.
    ///
    /// Parse this from the credential's own MSO. Deriving it from issuer
    /// metadata leaves every credential from a standards-conformant
    /// third-party issuer with no docType, and therefore unmatchable, while
    /// looking perfectly valid everywhere else.
    pub doctype: Option<String>,
    /// SD-JWT VC type, when this is an SD-JWT VC.
    pub vct: Option<String>,
    /// Primary line shown in the picker.
    pub title: String,
    /// Secondary line, typically the issuer.
    pub subtitle: String,
    /// Icon added via `add_icon` on `SirosBlobBuilder`, by its id.
    pub icon_id: Option<String>,
    /// Claims available for matching and display.
    pub claims: Vec<FfiClaim>,
}

/// Something this wallet can produce beyond what it stores, such as a ZK proof
/// over an mdoc.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiCapability {
    /// System identifier, e.g. `longfellow-libzk-v1`.
    pub system: String,
    /// Parameters that must also agree for the capability to apply.
    ///
    /// Supply the real ones. A ZK circuit is built for a fixed attribute
    /// count, so a request naming the right system with the wrong
    /// `num_attributes` is one this wallet cannot satisfy — and omitting the
    /// parameter turns that into a failure after the user has consented,
    /// rather than an entry that was never offered.
    pub params: std::collections::HashMap<String, String>,
}

/// Builds the blob a wallet registers with the platform.
///
/// The profile — protocols, format mappings, `meta` handling — is supplied by
/// this builder rather than by the caller. Wallets differ in what they *hold*
/// and what they *can do*, not usually in how DCQL should be interpreted, and
/// keeping the interpretation in one place is what stops two SDKs drifting
/// apart on it.
#[derive(uniffi::Object)]
pub struct SirosBlobBuilder {
    state: Mutex<BuilderState>,
}

#[derive(Default)]
struct BuilderState {
    credentials: Vec<FfiCredential>,
    icons: Vec<(String, Vec<u8>)>,
    zk_systems: Vec<FfiCapability>,
    debug: bool,
}

impl SirosBlobBuilder {
    /// Access the builder's state, recovering from a poisoned lock.
    ///
    /// A `Mutex` is poisoned when a thread panics while holding it. The usual
    /// reason to refuse a poisoned lock is that the data behind it may be
    /// half-updated and its invariants broken — but this state is three
    /// append-only collections and a flag, with no invariant spanning them, so
    /// there is nothing for a panic to have corrupted.
    ///
    /// Recovering rather than returning an error matters here because the
    /// alternative that was written first — `if let Ok(mut s) = lock()` —
    /// dropped the update and returned normally. A caller would add a
    /// credential, be told nothing, and find it missing from the blob. Silent
    /// data loss across an FFI boundary is close to undebuggable.
    fn state(&self) -> std::sync::MutexGuard<'_, BuilderState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[uniffi::export]
impl SirosBlobBuilder {
    /// A builder carrying the default SIROS matching profile.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(BuilderState::default()),
        }
    }

    /// Add a credential.
    pub fn add_credential(&self, credential: FfiCredential) {
        self.state().credentials.push(credential);
    }

    /// Add an icon, referenced by the `icon_id` field on `FfiCredential`.
    ///
    /// Stored once and shared: wallets routinely hold several credentials from
    /// one issuer, and repeating that issuer's logo per credential makes the
    /// registered payload grow with credentials rather than with issuers.
    pub fn add_icon(&self, id: String, bytes: Vec<u8>) {
        let mut s = self.state();
        s.icons.retain(|(existing, _)| existing != &id);
        s.icons.push((id, bytes));
    }

    /// Declare a ZK proof system this wallet can actually produce.
    ///
    /// Without this, a `mso_mdoc_zk` request matches nothing — which is the
    /// correct outcome for a wallet that cannot produce the proof.
    pub fn add_zk_system(&self, capability: FfiCapability) {
        self.state().zk_systems.push(capability);
    }

    /// Put matcher diagnostics into entry metadata.
    ///
    /// Development only. It writes matcher internals somewhere the platform
    /// stores them.
    pub fn set_debug(&self, debug: bool) {
        self.state().debug = debug;
    }

    /// Encode the blob to register.
    ///
    /// # Errors
    ///
    /// `BlobError::UnknownIcon` when a credential names an icon that was
    /// never added — a dangling reference would otherwise cost that credential
    /// its picture with nothing said. `BlobError::Encoding` if serialisation
    /// fails.
    pub fn build(&self) -> Result<Vec<u8>, BlobError> {
        let s = self.state();

        let mut icons = Vec::new();
        let mut offsets: BTreeMap<&str, IconRef> = BTreeMap::new();
        for (id, bytes) in &s.icons {
            let start = icons.len() as u32;
            icons.extend_from_slice(bytes);
            offsets.insert(
                id,
                IconRef {
                    start,
                    len: bytes.len() as u32,
                },
            );
        }

        let mut credentials = Vec::with_capacity(s.credentials.len());
        for c in &s.credentials {
            let icon = match &c.icon_id {
                Some(id) => {
                    Some(
                        *offsets
                            .get(id.as_str())
                            .ok_or_else(|| BlobError::UnknownIcon {
                                credential_id: c.id.clone(),
                                icon_id: id.clone(),
                            })?,
                    )
                }
                None => None,
            };
            credentials.push(Credential {
                id: c.id.clone(),
                format: c.format.clone(),
                doctype: c.doctype.clone(),
                vct: c.vct.clone(),
                title: c.title.clone(),
                subtitle: c.subtitle.clone(),
                icon,
                claims: c
                    .claims
                    .iter()
                    .map(|cl| Claim {
                        path: cl.path.clone(),
                        value: cl.value.clone(),
                        display: cl.display.clone(),
                        display_value: cl.display_value.clone(),
                    })
                    .collect(),
            });
        }

        let mut profile = MatchProfile::siros_default();
        profile.debug = s.debug;
        if !s.zk_systems.is_empty() {
            profile.capabilities.insert(
                ZK_CAPABILITY.to_string(),
                s.zk_systems
                    .iter()
                    .map(|c| Capability {
                        system: c.system.clone(),
                        params: c
                            .params
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    })
                    .collect(),
            );
        }

        let db = CredentialDatabase {
            version: siros_dc_matcher_core::db::VERSION,
            profile,
            credentials,
            icons,
        };
        db.to_cbor().map_err(|e| BlobError::Encoding {
            reason: e.to_string(),
        })
    }
}

impl Default for SirosBlobBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn credential(id: &str, icon_id: Option<&str>) -> FfiCredential {
        FfiCredential {
            id: id.into(),
            format: "mso_mdoc".into(),
            doctype: Some("org.iso.18013.5.1.mDL".into()),
            vct: None,
            title: "Driving Licence".into(),
            subtitle: "Transportstyrelsen".into(),
            icon_id: icon_id.map(str::to_owned),
            claims: vec![FfiClaim {
                path: vec!["org.iso.18013.5.1".into(), "family_name".into()],
                value: "Johansson".into(),
                display: "Family name".into(),
                display_value: None,
            }],
        }
    }

    #[test]
    fn builds_a_decodable_blob() {
        let b = SirosBlobBuilder::new();
        b.add_credential(credential("cred-1", None));
        let db = CredentialDatabase::from_cbor(&b.build().unwrap()).unwrap();
        assert_eq!(db.credentials.len(), 1);
        assert_eq!(
            db.credentials[0].doctype.as_deref(),
            Some("org.iso.18013.5.1.mDL")
        );
    }

    /// One icon shared by two credentials must be stored once.
    #[test]
    fn a_shared_icon_is_stored_once() {
        let b = SirosBlobBuilder::new();
        b.add_icon("issuer-logo".into(), vec![1, 2, 3, 4]);
        b.add_credential(credential("cred-1", Some("issuer-logo")));
        b.add_credential(credential("cred-2", Some("issuer-logo")));

        let db = CredentialDatabase::from_cbor(&b.build().unwrap()).unwrap();
        assert_eq!(db.icons.len(), 4);
        assert_eq!(db.icon_bytes(&db.credentials[0]), Some(&[1, 2, 3, 4][..]));
        assert_eq!(db.icon_bytes(&db.credentials[1]), Some(&[1, 2, 3, 4][..]));
    }

    /// A dangling icon reference is reported, not silently dropped.
    #[test]
    fn dangling_icon_reference_is_an_error() {
        let b = SirosBlobBuilder::new();
        b.add_credential(credential("cred-1", Some("never-added")));
        match b.build() {
            Err(BlobError::UnknownIcon {
                credential_id,
                icon_id,
            }) => {
                assert_eq!(credential_id, "cred-1");
                assert_eq!(icon_id, "never-added");
            }
            other => panic!("expected UnknownIcon, got {other:?}"),
        }
    }

    /// Without a declared ZK system there is no capability, so a mso_mdoc_zk
    /// request has nothing to satisfy it. That is the correct outcome for a
    /// wallet that cannot produce the proof.
    #[test]
    fn zk_capability_appears_only_when_declared() {
        let b = SirosBlobBuilder::new();
        b.add_credential(credential("cred-1", None));
        let db = CredentialDatabase::from_cbor(&b.build().unwrap()).unwrap();
        assert!(db.profile.capabilities.is_empty());

        let b = SirosBlobBuilder::new();
        b.add_credential(credential("cred-1", None));
        b.add_zk_system(FfiCapability {
            system: "longfellow-libzk-v1".into(),
            params: std::collections::HashMap::from([("num_attributes".into(), "4".into())]),
        });
        let db = CredentialDatabase::from_cbor(&b.build().unwrap()).unwrap();
        let systems = db.profile.capabilities.get("zk_system").unwrap();
        assert_eq!(systems[0].system, "longfellow-libzk-v1");
        // The parameter must survive: it is what distinguishes a circuit this
        // wallet has from one it does not.
        assert_eq!(systems[0].params.get("num_attributes").unwrap(), "4");
    }

    /// The ZK format rule is present by default, and maps onto plain mdoc.
    #[test]
    fn default_profile_routes_zk_requests_to_mdoc_storage() {
        let p = MatchProfile::siros_default();
        assert!(p.format_matches("mso_mdoc_zk", "mso_mdoc"));
        assert!(!p.format_matches("mso_mdoc_zk", "dc+sd-jwt"));
        assert!(!p.format_matches("something-new", "mso_mdoc"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod poison_tests {
    use super::*;

    /// A panic in another thread must not cost a later caller their data.
    ///
    /// The first version of this builder dropped the update and returned
    /// normally when the lock was poisoned: a caller added a credential, was
    /// told nothing, and found it missing from the blob. Across an FFI
    /// boundary that is close to undebuggable, so it gets a test.
    #[test]
    fn a_poisoned_lock_does_not_swallow_later_updates() {
        let builder = std::sync::Arc::new(SirosBlobBuilder::new());

        let b = std::sync::Arc::clone(&builder);
        let _ = std::thread::spawn(move || {
            let _guard = b.state.lock().unwrap();
            panic!("poison the lock");
        })
        .join();

        builder.add_credential(FfiCredential {
            id: "cred-after-poison".into(),
            format: "mso_mdoc".into(),
            doctype: Some("org.iso.18013.5.1.mDL".into()),
            vct: None,
            title: "Driving Licence".into(),
            subtitle: "Transportstyrelsen".into(),
            icon_id: None,
            claims: vec![],
        });

        let blob = builder.build().expect("build after poisoning");
        let db = CredentialDatabase::from_cbor(&blob).unwrap();
        assert_eq!(
            db.credentials.len(),
            1,
            "the credential added after poisoning was lost"
        );
        assert_eq!(db.credentials[0].id, "cred-after-poison");
    }
}
