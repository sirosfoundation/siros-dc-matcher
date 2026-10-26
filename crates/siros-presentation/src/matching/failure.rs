//! Why a request cannot be matched, why a Credential Query has no candidate, and why a request
//! has no offer.

use std::fmt;

use siros_credential::PointerError;
use siros_dcql::QueryId;
use siros_trust::AuthorityError;
use siros_zkp_req::ErrorCode;

use super::{Answered, ZkpRefusal};
use crate::credential::MatchCredential;

/// Why a request cannot be matched: the query as sent lacks a Credential Query of the parsed
/// one. The request is invalid (`invalid_request`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskedError {
    /// The query as sent lacks the Credential Query of this `id`.
    Unsent(QueryId),
}

impl AskedError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsent(_) => "query_unsent",
        }
    }
}

impl fmt::Display for AskedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for AskedError {}

/// Why a Credential Query has no candidate whatever the wallet holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryRefusal {
    /// `trusted_authorities` holds an `aki` value that encodes no keyIdentifier (TR3).
    Authorities(AuthorityError),
    /// A claims path the query selects is no claims path pointer (OpenID4VP 1.0, Section 7).
    ClaimPath(PointerError),
    /// The `zkp_req` query is refused.
    Zkp(ZkpRefusal),
}

impl QueryRefusal {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Authorities(error) => error.code(),
            Self::ClaimPath(error) => error.code(),
            Self::Zkp(refusal) => refusal.code(),
        }
    }

    /// The `zkp_req.md`, Section 5 code: `invalid_request` for `trusted_authorities` and a
    /// claims path.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Authorities(_) | Self::ClaimPath(_) => ErrorCode::InvalidRequest,
            Self::Zkp(refusal) => refusal.error_code(),
        }
    }
}

impl fmt::Display for QueryRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for QueryRefusal {}

/// Why a request has no offer. `R` is why a `zkp_req` candidate answers no option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure<R> {
    /// A Credential Query is refused.
    Refused {
        /// The query.
        query: QueryId,
        /// Why.
        refusal: QueryRefusal,
    },
    /// Credentials matched a `zkp_req` query, and none answers an option.
    Unproven {
        /// The query.
        query: QueryId,
        /// Why each credential answers none.
        reasons: Vec<R>,
    },
    /// No combination of the candidates satisfies the request.
    Unsatisfied,
}

impl<R> Failure<R> {
    /// A stable identifier: the refusal's code, `unproven` or `unsatisfied`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Refused { refusal, .. } => refusal.code(),
            Self::Unproven { .. } => "unproven",
            Self::Unsatisfied => "unsatisfied",
        }
    }

    /// The `zkp_req.md`, Section 5 code: the refusal's, else `access_denied`.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::Refused { refusal, .. } => refusal.error_code(),
            Self::Unproven { .. } | Self::Unsatisfied => ErrorCode::AccessDenied,
        }
    }
}

impl<C: MatchCredential, R: Clone> Answered<'_, C, R> {
    /// Why the request has no offer (`zkp_req.md`, Section 5): the first refused query whose
    /// code comes first of `invalid_request` and `vp_formats_not_supported`; else the first
    /// `zkp_req` query whose matched credentials all fail; else no combination.
    pub fn failure(&self) -> Failure<R> {
        let refused = self
            .queries
            .iter()
            .filter_map(|answers| Some((answers.id(), answers.refusal()?)))
            .min_by_key(|(_, refusal)| precedence(refusal.error_code()));
        if let Some((query, refusal)) = refused {
            return Failure::Refused {
                query: query.clone(),
                refusal: refusal.clone(),
            };
        }
        let unproven = self
            .queries
            .iter()
            .find(|answers| answers.candidates().is_empty() && !answers.excluded().is_empty());
        match unproven {
            Some(answers) => Failure::Unproven {
                query: answers.id().clone(),
                reasons: answers
                    .excluded()
                    .iter()
                    .map(|excluded| excluded.reason().clone())
                    .collect(),
            },
            None => Failure::Unsatisfied,
        }
    }
}

/// The order of the codes of Section 5: `invalid_request` first.
fn precedence(code: ErrorCode) -> u8 {
    match code {
        ErrorCode::InvalidRequest => 0,
        ErrorCode::VpFormatsNotSupported => 1,
        ErrorCode::AccessDenied => 2,
    }
}
