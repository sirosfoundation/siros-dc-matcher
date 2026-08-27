//! The match profile: what this wallet accepts and what it can actually do.
//!
//! The matcher ships as a binary inside an APK, so changing its behaviour by
//! rebuilding it costs a release cycle. The rules therefore travel with the
//! registered credential blob instead, and adding a credential format becomes
//! a configuration change plus a re-registration — something every wallet
//! already does whenever its credential set changes.
//!
//! The profile is deliberately not a programming language. [`Op`] is closed,
//! there is no arithmetic and no user-supplied expression. Anything past that
//! boundary is a matcher release, not a config change.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Comparison operators available to a [`MetaRule`]. Closed by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Credential field equals the requested value.
    Eq,
    /// Credential field appears in the requested list.
    In,
    /// Credential field starts with the requested value.
    Prefix,
    /// Credential field is present, whatever its value.
    Exists,
    /// Meta key carries no matching constraint. Named explicitly so that
    /// "we chose to ignore this" is distinguishable from "we forgot it".
    Ignore,
}

/// What happens when a query names a format the profile does not describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnknownFormat {
    /// Emit nothing. The correct production setting.
    #[default]
    Reject,
    /// Match any stored credential. Interop debugging only — it will offer
    /// credentials the wallet cannot actually present.
    MatchAny,
}

/// How a requested query format maps onto stored credentials.
///
/// The indirection is the point: `mso_mdoc_zk` is a *presentation-time
/// transform* of an ordinary `mso_mdoc` credential, not a separate storage
/// format, so there is no distinct ZK credential on the device to match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FormatRule {
    /// Format as it appears in the verifier's DCQL query.
    pub query_format: String,
    /// Stored formats this query format may be satisfied from.
    pub stored_formats: Vec<String>,
    /// Capabilities that must hold before a match is offered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<Requirement>,
}

/// A capability this wallet must actually have for a match to be offered.
///
/// Checking this before the picker rather than during presentation is the
/// whole point: offering an entry the wallet cannot honour walks the user
/// through a consent screen and then fails.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Requirement {
    /// Capability name, looked up in the profile's capability map.
    pub capability: String,
    /// `meta` key carrying the verifier's acceptable values.
    pub from_meta: String,
}

/// How one `meta` key constrains a match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaRule {
    /// Key within the DCQL query's `meta` object, e.g. `doctype_value`.
    pub meta_key: String,
    /// Credential field to compare against. Absent for [`Op::Ignore`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Comparison to apply.
    pub op: Op,
}

/// A protocol this wallet answers to, and where its DCQL query lives.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtocolRule {
    /// Protocol identifier as it appears in the DC API request.
    pub id: String,
    /// Which request parser to use.
    pub parser: Parser,
}

/// How to read a request for a given protocol.
///
/// A closed set, not a free-form pointer: a matcher that can be pointed at
/// arbitrary places in a request is a matcher whose behaviour cannot be
/// reviewed. New shapes are a matcher release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Parser {
    /// OpenID4VP 1.0 — the DCQL query is at `data.dcql_query`.
    Openid4vpV1,
    /// ISO 18013-7 mdoc API.
    IsoMdocApi,
}

/// What this wallet can actually produce, beyond what it stores.
///
/// Checked before an entry is offered, not during presentation. Offering an
/// entry the wallet cannot honour walks the user through a consent screen and
/// then fails — the worst possible place to discover a capability gap.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Capability {
    /// System identifier, e.g. `longfellow-libzk-v1`.
    pub system: String,
    /// Parameters that must also agree.
    ///
    /// These are not decoration. A ZK circuit is built for a fixed number of
    /// attributes, so a request naming the right system with the wrong
    /// `num_attributes` is one this wallet cannot satisfy — and finding that
    /// out at proof-generation time rather than at match time is how it
    /// surfaces as an unexplained failure after consent.
    #[serde(default)]
    pub params: std::collections::BTreeMap<String, String>,
}

/// The complete set of rules a wallet registers alongside its credentials.
///
/// This is what makes the matcher configurable rather than merely
/// customisable: the binary ships inside an APK, so changing its behaviour by
/// rebuilding costs a release cycle, whereas changing this costs a
/// re-registration — something wallets already do on every credential change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MatchProfile {
    /// Protocols to answer, in preference order.
    #[serde(default)]
    pub protocols: Vec<ProtocolRule>,
    /// How requested formats map onto stored ones.
    #[serde(default)]
    pub formats: Vec<FormatRule>,
    /// How `meta` keys constrain a match.
    #[serde(default)]
    pub meta_rules: Vec<MetaRule>,
    /// Capabilities, keyed by the name a [`Requirement`] refers to.
    #[serde(default)]
    pub capabilities: std::collections::BTreeMap<String, Vec<Capability>>,
    /// What to do with a query format no [`FormatRule`] describes.
    #[serde(default)]
    pub unknown_format: UnknownFormat,
    /// Emit diagnostics into entry metadata. Never enable in production: it
    /// puts matcher internals somewhere the platform stores them.
    #[serde(default)]
    pub debug: bool,
}

impl MatchProfile {
    /// The rule for a requested format, if the profile describes one.
    pub fn format_rule(&self, query_format: &str) -> Option<&FormatRule> {
        self.formats.iter().find(|f| f.query_format == query_format)
    }

    /// Whether a stored format can satisfy a requested one.
    ///
    /// Not the same question as equality. `mso_mdoc_zk` is satisfied by an
    /// ordinary `mso_mdoc` credential, because producing a ZK proof is a
    /// presentation-time transform rather than a storage format — there is no
    /// separate ZK credential on the device to find.
    pub fn format_matches(&self, query_format: &str, stored_format: &str) -> bool {
        match self.format_rule(query_format) {
            Some(rule) => rule.stored_formats.iter().any(|f| f == stored_format),
            None => match self.unknown_format {
                UnknownFormat::Reject => false,
                UnknownFormat::MatchAny => true,
            },
        }
    }

    /// The parser for a protocol, if this wallet answers to it.
    pub fn parser_for(&self, protocol: &str) -> Option<Parser> {
        self.protocols
            .iter()
            .find(|p| p.id == protocol)
            .map(|p| p.parser)
    }
}

/// Capability name a `mso_mdoc_zk` format rule refers to.
pub const ZK_CAPABILITY: &str = "zk_system";

/// `mso_mdoc_zk` maps onto ordinary `mso_mdoc` storage because producing a ZK
/// proof is a presentation-time transform, not a storage format — there is no
/// separate ZK credential on the device to find. It carries a capability
/// requirement so the entry is only offered when the wallet can actually
/// produce the proof the verifier asked for.
impl MatchProfile {
    /// The profile SIROS wallets register.
    pub fn siros_default() -> Self {
        Self {
            protocols: vec![
                ProtocolRule {
                    id: "openid4vp-v1-unsigned".into(),
                    parser: Parser::Openid4vpV1,
                },
                ProtocolRule {
                    id: "openid4vp-v1-signed".into(),
                    parser: Parser::Openid4vpV1,
                },
                ProtocolRule {
                    id: "openid4vp-v1-multisigned".into(),
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
                    query_format: "dc+sd-jwt".into(),
                    stored_formats: vec!["dc+sd-jwt".into()],
                    requires: vec![],
                },
                FormatRule {
                    query_format: "mso_mdoc_zk".into(),
                    stored_formats: vec!["mso_mdoc".into()],
                    requires: vec![Requirement {
                        capability: ZK_CAPABILITY.into(),
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
                // Carried through to the wallet rather than used for matching: a
                // pseudonym context changes what is produced, not which credential
                // can produce it.
                MetaRule {
                    meta_key: "ppid_context".into(),
                    field: None,
                    op: Op::Ignore,
                },
            ],
            capabilities: BTreeMap::new(),
            unknown_format: UnknownFormat::Reject,
            debug: false,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn unknown_format_defaults_to_reject() {
        assert_eq!(UnknownFormat::default(), UnknownFormat::Reject);
    }

    /// A ZK format rule maps onto ordinary mdoc storage and carries a
    /// capability requirement — the shape the whole profile exists for.
    #[test]
    fn zk_format_rule_round_trips() {
        let json = r#"{"query_format":"mso_mdoc_zk","stored_formats":["mso_mdoc"],
                       "requires":[{"capability":"zk_system","from_meta":"zk_system_type"}]}"#;
        let rule: FormatRule = serde_json::from_str(json).unwrap();
        assert_eq!(rule.stored_formats, ["mso_mdoc"]);
        assert_eq!(rule.requires[0].from_meta, "zk_system_type");
    }

    /// The reason this whole indirection exists: a ZK request is satisfied by
    /// an ordinary mdoc credential.
    #[test]
    fn zk_query_format_is_satisfied_by_plain_mdoc_storage() {
        let mut p = MatchProfile::default();
        p.formats.push(FormatRule {
            query_format: "mso_mdoc_zk".into(),
            stored_formats: vec!["mso_mdoc".into()],
            requires: vec![],
        });
        assert!(p.format_matches("mso_mdoc_zk", "mso_mdoc"));
        assert!(!p.format_matches("mso_mdoc_zk", "dc+sd-jwt"));
    }

    /// An undescribed format is refused by default. The permissive setting
    /// exists for interop debugging and offers credentials the wallet may not
    /// be able to present.
    #[test]
    fn unknown_format_is_refused_unless_explicitly_permissive() {
        let mut p = MatchProfile::default();
        assert!(!p.format_matches("something-new", "mso_mdoc"));
        p.unknown_format = UnknownFormat::MatchAny;
        assert!(p.format_matches("something-new", "mso_mdoc"));
    }

    #[test]
    fn parser_is_resolved_per_protocol() {
        let p = MatchProfile {
            protocols: vec![ProtocolRule {
                id: "openid4vp-v1-signed".into(),
                parser: Parser::Openid4vpV1,
            }],
            ..Default::default()
        };
        assert_eq!(
            p.parser_for("openid4vp-v1-signed"),
            Some(Parser::Openid4vpV1)
        );
        assert_eq!(p.parser_for("org.iso.mdoc"), None);
    }
}
