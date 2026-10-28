//! How a plan or an offer contradicts the matching it was built from.

use siros_zkp_req_nym_auth::policy::RequestRefusal;

use crate::ids::{CandidateIndex, QueryIndex};

/// How a plan contradicts itself: a position or an answer that a list of the plan lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Inconsistency {
    /// A member names a query the matching lacks.
    Query(QueryIndex),
    /// A member names a candidate its query lacks.
    Candidate(QueryIndex, CandidateIndex),
    /// A proof answers a query without a nym_auth query.
    ZkpQuery(QueryIndex),
    /// A proof answers a request that is no nym_auth request, for this reason.
    NymAuthRequest(#[source] RequestRefusal),
    /// A binding names an entry the request lacks.
    Entry,
    /// A binding names a credential the offer lacks.
    BoundCredential,
}

impl Inconsistency {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Query(_) => "plan_query_unknown",
            Self::Candidate(..) => "plan_candidate_unknown",
            Self::ZkpQuery(_) => "plan_zkp_query_missing",
            Self::NymAuthRequest(_) => "plan_nym_auth_request_missing",
            Self::Entry => "plan_entry_unknown",
            Self::BoundCredential => "plan_bound_credential_unknown",
        }
    }
}
