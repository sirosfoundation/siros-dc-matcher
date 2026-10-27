//! The `dcql_query` of an unverified request.

use serde_json::Value;
use siros_dcql::DcqlQuery;

use super::NoQuery;

/// A `dcql_query` as sent, and its DCQL form.
///
/// DCQL has no form for one shape: a `zkp_req` credential query with an object under
/// `claims`, as in the rulebook example. `claims` means nothing for `zkp_req`, whose requests
/// live in `_req`, and the `zkp_req` planner reads it from the query as sent.
#[derive(Debug, Clone, PartialEq)]
pub struct UnverifiedQuery {
    raw: Value,
    form: QueryForm,
}

/// What DCQL represents of a `dcql_query`.
#[derive(Debug, Clone, PartialEq)]
enum QueryForm {
    /// The whole query.
    Whole(DcqlQuery),
    /// The query with the `claims` of its `zkp_req` credential queries left out.
    WithoutZkpReqClaims(DcqlQuery),
}

impl UnverifiedQuery {
    /// Reads a raw `dcql_query`.
    ///
    /// When the parse fails and the query holds a `zkp_req` credential query, the query is
    /// parsed again with the `claims` of its `zkp_req` credential queries left out.
    ///
    /// # Errors
    ///
    /// [`NoQuery::Malformed`], with the first parse's message, when both parses fail.
    pub fn parse(raw: Value) -> Result<Self, NoQuery> {
        let first_error = match DcqlQuery::parse(&raw) {
            Ok(query) => {
                return Ok(Self {
                    raw,
                    form: QueryForm::Whole(query),
                })
            }
            Err(e) => e,
        };
        let credentials = raw.get("credentials").and_then(Value::as_array);
        if !credentials.is_some_and(|credentials| credentials.iter().any(is_zkp_req)) {
            return Err(NoQuery::Malformed(first_error.to_string()));
        }
        let mut stripped = raw.clone();
        stripped
            .get_mut("credentials")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
            .filter(|credential| is_zkp_req(credential))
            .filter_map(Value::as_object_mut)
            .for_each(|credential| drop(credential.remove("claims")));
        match DcqlQuery::parse(&stripped) {
            Ok(query) => Ok(Self {
                raw,
                form: QueryForm::WithoutZkpReqClaims(query),
            }),
            Err(_) => Err(NoQuery::Malformed(first_error.to_string())),
        }
    }

    /// The query exactly as sent.
    #[must_use]
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// The query as DCQL; `None` for a query DCQL represents only with the `claims` of its
    /// `zkp_req` credential queries left out.
    #[must_use]
    pub fn typed(&self) -> Option<&DcqlQuery> {
        match &self.form {
            QueryForm::Whole(query) => Some(query),
            QueryForm::WithoutZkpReqClaims(_) => None,
        }
    }

    /// The query the DCQL engine matches: [`Self::typed`], or the query with the `claims` of
    /// its `zkp_req` credential queries left out.
    ///
    /// A `zkp_req` credential query with no claims selects none, which is what the format
    /// means; the planner reads what was asked from [`Self::raw`].
    #[must_use]
    pub fn matching_query(&self) -> &DcqlQuery {
        match &self.form {
            QueryForm::Whole(query) | QueryForm::WithoutZkpReqClaims(query) => query,
        }
    }
}

/// Whether the credential query `credential` asks for the `zkp_req` format.
fn is_zkp_req(credential: &Value) -> bool {
    credential.get("format").and_then(Value::as_str) == Some("zkp_req")
}
