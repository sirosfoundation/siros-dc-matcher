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
}
