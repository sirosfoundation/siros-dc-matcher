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
/// A `zkp_req` presentation is a proof about an ordinary stored `mso_mdoc`
/// credential, so its query format names a stored format other than itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FormatRule {
    /// Format as it appears in the verifier's DCQL query.
    pub query_format: String,
    /// Stored formats this query format may be satisfied from.
    pub stored_formats: Vec<String>,
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

/// A `zkp_req` circuit this wallet can prove with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Capability {
    /// Proof system, e.g. `longfellow-libzk-v1`.
    pub system: String,
    /// The circuit's parameters: [`SYSTEM_ID_PARAM`], and optionally
    /// [`FUNCTIONS_PARAM`], [`CREDENTIAL_TYPE_PARAM`] and [`CAPABILITIES_PARAM`].
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
    /// Capabilities, keyed by their family, such as [`ZKP_REQ_CAPABILITY`].
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
    /// Not the same question as equality: `zkp_req` is satisfied by an
    /// ordinary `mso_mdoc` credential.
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

/// Capability family for `zkp_req` circuits a wallet can prove with.
///
/// Every entry is one circuit: [`Capability::system`] is its proof system, and
/// its params are opaque strings the matcher reads only as follows —
/// [`SYSTEM_ID_PARAM`] is compared with the verifier's `system_id_values`,
/// and [`FUNCTIONS_PARAM`], when present, bounds which functions it supports.
pub const ZKP_REQ_CAPABILITY: &str = "zkp_req";

/// Param naming a circuit, matched against the verifier's `system_id_values`.
pub const SYSTEM_ID_PARAM: &str = "system_id";

/// Param listing the function ids a circuit supports, comma-separated.
///
/// Optional. A circuit that declares none is not filtered by function: the
/// catalog carries no function-support metadata yet, and guessing at it would
/// reject requests the wallet can serve.
pub const FUNCTIONS_PARAM: &str = "functions";

/// Param restricting a circuit to one credential type (an mdoc doctype or an
/// SD-JWT VC `vct`), compared with the request's `meta`.
///
/// Optional. Absent means unrestricted, as before. A request whose `meta`
/// names neither `doctype_value` nor `vct_values` is not offered a restricted
/// circuit. Ignored when [`CAPABILITIES_PARAM`] is present.
pub const CREDENTIAL_TYPE_PARAM: &str = "credential_type";

/// Param carrying the catalog's `capabilities` object for the circuit, as a
/// JSON string (see [`crate::circuit_capabilities`]).
///
/// Optional. When present it replaces [`FUNCTIONS_PARAM`] and
/// [`CREDENTIAL_TYPE_PARAM`], and a value that does not parse means the
/// circuit is not offered.
pub const CAPABILITIES_PARAM: &str = "capabilities";

/// The format a `zkp_req` query is asked in.
pub const ZKP_REQ_FORMAT: &str = "zkp_req";

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
                // org.iso.mdoc is deliberately absent. The profile states
                // what this wallet answers, and the matcher has no ISO
                // 18013-7 reader yet — advertising it would make a request
                // offering only that protocol look supported and then match
                // nothing. Add it here in the same change that adds a parser.
            ],
            formats: vec![
                FormatRule {
                    query_format: "mso_mdoc".into(),
                    stored_formats: vec!["mso_mdoc".into()],
                },
                FormatRule {
                    query_format: "dc+sd-jwt".into(),
                    stored_formats: vec!["dc+sd-jwt".into()],
                },
                // A `zkp_req` presentation is a proof about an ordinary stored
                // mdoc. The evaluator checks the circuit capabilities against
                // the planned request.
                FormatRule {
                    query_format: ZKP_REQ_FORMAT.into(),
                    stored_formats: vec!["mso_mdoc".into()],
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
