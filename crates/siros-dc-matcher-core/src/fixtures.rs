//! A canonical test wallet.
//!
//! Three test suites need "a wallet holding one mdoc driving licence, able to
//! prove in ZK or not": the profile evaluator's, the FFI's, and the test
//! host's, which drives the real `matcher.wasm`. Written three times they
//! drift, and a fixture that drifts silently changes what its assertions mean
//! — the same argument that put [`crate::evaluator::resolve`] in one place.
//!
//! Behind the `test-fixtures` feature so it is a dev-time facility, not part
//! of the shipped surface.

use crate::db::{Claim, Credential, CredentialDatabase};
use crate::profile::{Capability, MatchProfile, ZK_CAPABILITY};

/// A wallet holding one ISO mdoc driving licence.
///
/// Two claims, deliberately: one requested and one not, so a test asserting
/// that only the requested claims are disclosed has something to catch.
pub fn wallet(zk_systems: Vec<Capability>) -> CredentialDatabase {
    let mut profile = MatchProfile::siros_default();
    if !zk_systems.is_empty() {
        profile
            .capabilities
            .insert(ZK_CAPABILITY.to_string(), zk_systems);
    }

    let mut db = CredentialDatabase::new(profile);
    db.credentials.push(Credential {
        id: "mdl-1".into(),
        // Stored as an ordinary mdoc. There is no such thing as a stored ZK
        // credential — the proof is produced at presentation time.
        format: "mso_mdoc".into(),
        doctype: Some("org.iso.18013.5.1.mDL".into()),
        vct: None,
        title: "Driving Licence".into(),
        subtitle: "Transportstyrelsen".into(),
        icon: None,
        claims: vec![
            Claim {
                path: vec!["org.iso.18013.5.1".into(), "age_over_18".into()],
                value: "true".into(),
                display: "Over 18".into(),
                display_value: Some("Yes".into()),
            },
            Claim {
                path: vec!["org.iso.18013.5.1".into(), "family_name".into()],
                value: "Johansson".into(),
                display: "Family name".into(),
                display_value: None,
            },
        ],
    });
    db
}

/// A Longfellow capability, optionally pinned to an attribute count.
///
/// Passing `None` models a *nominal* capability — the system, any shape, with
/// circuit availability checked at proof time. That is how this SDK's own
/// systems declare themselves, so it is the case worth having easy to write.
pub fn longfellow(num_attributes: Option<&str>) -> Capability {
    Capability {
        system: "longfellow-libzk-v1".into(),
        params: num_attributes
            .map(|n| {
                [("num_attributes".to_string(), n.to_string())]
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default(),
    }
}
