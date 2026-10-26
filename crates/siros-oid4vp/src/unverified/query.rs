//! The `dcql_query` of an unverified request.

use serde::Deserialize;
use serde_json::Value;
use siros_dcql::DcqlQuery;

use super::NoQuery;

/// A `dcql_query` as sent, and its DCQL form when DCQL represents it.
///
/// DCQL has no form for one shape: a `zkp_req` credential query with an object under
/// `claims`, as in the rulebook example. Such a query keeps only its raw form, and the
/// `zkp_req` planner reads it from there.
#[derive(Debug, Clone, PartialEq)]
pub struct UnverifiedQuery {
    raw: Value,
    typed: Option<DcqlQuery>,
}

impl UnverifiedQuery {
    /// Reads a raw `dcql_query`.
    ///
    /// When the typed parse fails, the query is parsed again without its `zkp_req`
    /// credential queries: if the rest parses, the failure was theirs and the query keeps
    /// only its raw form.
    ///
    /// # Errors
    ///
    /// [`NoQuery::Malformed`], with the typed parser's message, for any other failure.
    pub fn parse(raw: Value) -> Result<Self, NoQuery> {
        let first_error = match DcqlQuery::deserialize(&raw) {
            Ok(query) => {
                return Ok(Self {
                    raw,
                    typed: Some(query),
                })
            }
            Err(e) => e,
        };
        let is_zkp_req = |c: &Value| c.get("format").and_then(Value::as_str) == Some("zkp_req");
        let (Some(credentials), Some(object)) = (
            raw.get("credentials").and_then(Value::as_array),
            raw.as_object(),
        ) else {
            return Err(NoQuery::Malformed(first_error.to_string()));
        };
        if !credentials.iter().any(is_zkp_req) {
            return Err(NoQuery::Malformed(first_error.to_string()));
        }
        let mut rest = object.clone();
        rest.insert(
            "credentials".to_string(),
            Value::Array(
                credentials
                    .iter()
                    .filter(|c| !is_zkp_req(c))
                    .cloned()
                    .collect(),
            ),
        );
        match DcqlQuery::deserialize(&Value::Object(rest)) {
            Ok(_) => Ok(Self { raw, typed: None }),
            Err(_) => Err(NoQuery::Malformed(first_error.to_string())),
        }
    }

    /// The query exactly as sent.
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// The query as DCQL; `None` for a `zkp_req` query with object `claims`.
    #[must_use]
    pub fn typed(&self) -> Option<&DcqlQuery> {
        self.typed.as_ref()
    }

    /// The query the DCQL engine matches: [`Self::typed`], or the raw query with the `claims`
    /// of its `zkp_req` credential queries left out.
    ///
    /// `claims` means nothing for `zkp_req`, whose requests live in `_req`. A `zkp_req`
    /// credential query with no claims selects none, which is what the format means; the
    /// planner reads what was asked from [`Self::raw`].
    #[must_use]
    pub fn matching_query(&self) -> Option<DcqlQuery> {
        if let Some(query) = &self.typed {
            return Some(query.clone());
        }
        let mut raw = self.raw.clone();
        for credential in raw.get_mut("credentials")?.as_array_mut()? {
            if credential.get("format").and_then(Value::as_str) == Some("zkp_req") {
                if let Some(object) = credential.as_object_mut() {
                    object.remove("claims");
                }
            }
        }
        DcqlQuery::deserialize(&raw).ok()
    }
}
