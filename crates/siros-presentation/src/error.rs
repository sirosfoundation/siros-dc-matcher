//! Why a plan failed. Each error has a stable code and the OpenID4VP 1.0, Section 8.5 code the
//! verifier receives.

use siros_display::DisplayError;
use siros_oid4vp::{ErrorCode, HttpsUrl};
use siros_transaction_data::TransactionDataError;

use crate::ids::{CandidateIndex, QueryIndex};
use crate::matching::{AskedError, ChoiceError, Failure};
use crate::plan::Unproven;

/// Why the core gives no plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum PresentationError {
    /// A Credential Query of the request breaks a rule (`invalid_request`).
    Asked(#[from] AskedError),
    /// The wallet has no offer for the request, and why.
    NoOffer(#[from] Failure<Unproven>),
    /// An entry of `transaction_data`, or its binding to an offer, breaks a rule. The code is
    /// its own.
    TransactionData(#[from] TransactionDataError),
    /// The consent view cannot show a credential. The code is the display's.
    Display(#[from] DisplayError),
    /// The host answered a fetch of this URL twice.
    FetchRepeated(HttpsUrl),
    /// The plan contradicts itself.
    Inconsistent(#[from] Inconsistency),
    /// A proof choice gives no option or usable pair of its query.
    Choice(#[from] ChoiceError),
}

/// How a plan contradicts itself: a position or an answer that a list of the plan lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum Inconsistency {
    /// A member names a query the matching lacks.
    Query(QueryIndex),
    /// A member names a candidate its query lacks.
    Candidate(QueryIndex, CandidateIndex),
    /// A proof answers a query without a nym_auth query.
    ZkpQuery(QueryIndex),
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
            Self::Entry => "plan_entry_unknown",
            Self::BoundCredential => "plan_bound_credential_unknown",
        }
    }
}

impl PresentationError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Asked(e) => e.code(),
            Self::NoOffer(failure) => failure.code(),
            Self::TransactionData(e) => e.code(),
            Self::Display(e) => e.code(),
            Self::FetchRepeated(_) => "fetch_repeated",
            Self::Inconsistent(e) => e.code(),
            Self::Choice(e) => e.code(),
        }
    }

    /// The error the verifier receives (Section 8.5): `invalid_request` for a Credential Query
    /// that breaks a rule, the failure's own code when no offer remains,
    /// `invalid_transaction_data` for transaction data, and `access_denied` for every failure
    /// of the wallet, as `zkp_req.md`, Section 5 sends one.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Asked(_) => ErrorCode::InvalidRequest,
            Self::NoOffer(failure) => oid4vp_code(failure.error_code()),
            Self::TransactionData(e) => e.error_code(),
            Self::Display(_) | Self::FetchRepeated(_) | Self::Inconsistent(_) | Self::Choice(_) => {
                ErrorCode::AccessDenied
            }
        }
    }
}

/// The OpenID4VP 1.0, Section 8.5 code of a `zkp_req.md`, Section 5 code.
fn oid4vp_code(code: siros_zkp_req::ErrorCode) -> ErrorCode {
    match code {
        siros_zkp_req::ErrorCode::InvalidRequest => ErrorCode::InvalidRequest,
        siros_zkp_req::ErrorCode::VpFormatsNotSupported => ErrorCode::VpFormatsNotSupported,
        siros_zkp_req::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
    }
}
