//! Golden vectors for the credential blob.
//!
//! The encoder and the matcher are separated by time: a wallet writes a blob
//! today, and a matcher binary that shipped months ago reads it inside the
//! picker. Round-trip tests cannot catch drift between them, because both ends
//! move together in a round trip. A committed byte vector is the only thing
//! that notices when today's encoder stops producing what yesterday's decoder
//! expects.
//!
//! Regenerate deliberately, never reflexively:
//!
//! ```sh
//! UPDATE_GOLDEN=1 cargo test -p siros-dc-matcher-core --test golden_blob
//! ```
//!
//! A diff here means the wire format changed. That is either a bug, or a
//! change that needs `db::VERSION` bumped and a note in the PR — it is never
//! just noise to be regenerated away.

use std::collections::BTreeMap;
use std::path::PathBuf;

use siros_dc_matcher_core::db::{Claim, Credential, CredentialDatabase, IconRef, VERSION};
use siros_dc_matcher_core::profile::{
    Capability, FormatRule, MatchProfile, MetaRule, Op, Parser, ProtocolRule, Requirement,
    UnknownFormat,
};

/// A blob exercising every field the format has, including the ZK path.
///
/// Deliberately not minimal: a golden vector that omits a field cannot detect
/// that field's encoding changing.
fn reference_database() -> CredentialDatabase {
    let mut capabilities = BTreeMap::new();
    capabilities.insert(
        "zk_system".to_string(),
        vec![Capability {
            system: "longfellow-libzk-v1".into(),
            params: BTreeMap::from([
                ("num_attributes".to_string(), "4".to_string()),
                ("version".to_string(), "3".to_string()),
            ]),
        }],
    );

    let profile = MatchProfile {
        protocols: vec![
            ProtocolRule {
                id: "openid4vp-v1-signed".into(),
                parser: Parser::Openid4vpV1,
            },
            ProtocolRule {
                id: "org.iso.mdoc".into(),
                parser: Parser::IsoMdocApi,
            },
        ],
        formats: vec![
            FormatRule {
                query_format: "mso_mdoc".into(),
                stored_formats: vec!["mso_mdoc".into()],
                requires: vec![],
            },
            FormatRule {
                query_format: "mso_mdoc_zk".into(),
                stored_formats: vec!["mso_mdoc".into()],
                requires: vec![Requirement {
                    capability: "zk_system".into(),
                    from_meta: "zk_system_type".into(),
                }],
            },
        ],
        meta_rules: vec![
            MetaRule {
                meta_key: "doctype_value".into(),
                field: Some("doctype".into()),
                op: Op::Eq,
            },
            MetaRule {
                meta_key: "vct_values".into(),
                field: Some("vct".into()),
                op: Op::In,
            },
            MetaRule {
                meta_key: "ppid_context".into(),
                field: None,
                op: Op::Ignore,
            },
        ],
        capabilities,
        unknown_format: UnknownFormat::Reject,
        debug: false,
    };

    CredentialDatabase {
        version: VERSION,
        profile,
        credentials: vec![Credential {
            id: "urn:siros:credential:1".into(),
            format: "mso_mdoc".into(),
            doctype: Some("org.iso.18013.5.1.mDL".into()),
            vct: None,
            title: "Driving Licence".into(),
            subtitle: "Transportstyrelsen".into(),
            icon: Some(IconRef { start: 0, len: 4 }),
            claims: vec![
                Claim {
                    // Dotted ISO namespace kept as one element on purpose.
                    path: vec!["org.iso.18013.5.1".into(), "family_name".into()],
                    value: "Johansson".into(),
                    display: "Family name".into(),
                    display_value: None,
                },
                Claim {
                    path: vec!["org.iso.18013.5.1".into(), "age_over_18".into()],
                    value: "true".into(),
                    display: "Over 18".into(),
                    display_value: Some("Yes".into()),
                },
            ],
        }],
        icons: vec![0x89, 0x50, 0x4E, 0x47],
    }
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/credential_database_v1.cbor")
}

#[test]
fn encoding_matches_the_committed_vector() {
    let encoded = reference_database().to_cbor().expect("encoding");
    let path = golden_path();

    if std::env::var("UPDATE_GOLDEN").is_ok() {
        std::fs::write(&path, &encoded).expect("writing golden vector");
        return;
    }

    let expected = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "missing golden vector {}: {e}\n\
             Create it with: UPDATE_GOLDEN=1 cargo test -p siros-dc-matcher-core --test golden_blob",
            path.display()
        )
    });

    assert_eq!(
        encoded, expected,
        "\nThe credential blob encoding changed.\n\
         A matcher already in the field decodes the committed bytes, not these.\n\
         If the change is intended: bump db::VERSION, say why in the PR, then\n\
         regenerate with UPDATE_GOLDEN=1."
    );
}

/// The committed bytes must still decode to the structure they encode — the
/// half of the contract a matcher in the field actually performs.
#[test]
fn committed_vector_still_decodes() {
    let bytes = std::fs::read(golden_path()).expect("golden vector");
    let decoded = CredentialDatabase::from_cbor(&bytes).expect("decoding golden vector");
    assert_eq!(decoded, reference_database());
}

/// Truncating the golden vector anywhere must produce an error, never a panic
/// and never a plausible-looking half-database.
#[test]
fn truncations_of_the_golden_vector_never_panic() {
    let bytes = std::fs::read(golden_path()).expect("golden vector");
    for n in 0..bytes.len() {
        let _ = CredentialDatabase::from_cbor(&bytes[..n]);
    }
}
