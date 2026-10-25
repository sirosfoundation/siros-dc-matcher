//! The consent model: match every query, show one consent screen, then prove.
//!
//! A presenter matches one Credential Query against the Wallet's credentials and returns a
//! [`Match`]. The Wallet matches every query of a request, shows one consent screen for the
//! [`Candidate`]s, and proves them. When a query has no candidate, [`failure_code`] gives the
//! error the Wallet sends for the request (`zkp_req`, Section 5).

use crate::outcome::ErrorCode;

/// A credential that can answer a query, with the option and the pair that answer it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The Wallet's identifier of the credential.
    pub credential_id: String,
    /// The system of the pair (Section 1.3).
    pub system_id: String,
    /// The proof backend of the pair (Section 1.3).
    pub proof_backend: String,
    /// The answered option's index in `_req_sets`; `None` for a query without them.
    pub req_set: Option<usize>,
    /// The `_req` indexes of the answered option.
    pub items: Vec<usize>,
    /// The parameters the User supplies at proving time.
    pub inputs: Vec<UserInput>,
}

/// A parameter whose value the User supplies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInput {
    /// The `_req` index of the item.
    pub item: usize,
    /// The parameter's name.
    pub param: String,
}

/// A credential that cannot answer any option, and why. For the User only: the Verifier
/// receives `access_denied` without a description (Section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged<E> {
    /// The Wallet's identifier of the credential.
    pub credential_id: String,
    /// Why each option this credential has a usable pair for fails, in the Verifier's order.
    pub errors: Vec<E>,
}

/// An option without a usable pair, and why (Section 1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionRefusal<P> {
    /// The option's index in `_req_sets`; `None` for a query without them.
    pub req_set: Option<usize>,
    /// For each system the Wallet runs, why it forms no usable pair.
    pub systems: Vec<(String, P)>,
}

/// The outcome of matching one Credential Query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match<R, P, E> {
    /// The credentials that can answer, in the Wallet's order of preference.
    Candidates(Vec<Candidate>),
    /// No credential can answer (Section 5: `access_denied`).
    Rejected(Vec<Judged<E>>),
    /// No option has a usable pair (Section 5: `vp_formats_not_supported`).
    Unsupported(Vec<OptionRefusal<P>>),
    /// The query breaks a rule (Section 5: `invalid_request`).
    Invalid(R),
}

impl<R, P, E> Match<R, P, E> {
    /// The error code of a query without candidates.
    pub fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Candidates(c) if !c.is_empty() => None,
            Self::Candidates(_) | Self::Rejected(_) => Some(ErrorCode::AccessDenied),
            Self::Unsupported(_) => Some(ErrorCode::VpFormatsNotSupported),
            Self::Invalid(_) => Some(ErrorCode::InvalidRequest),
        }
    }
}

/// The error a Wallet sends for a request when some query has no candidate: the first of
/// `invalid_request`, `vp_formats_not_supported` and `access_denied` that a query gives.
/// `None` when every query has a candidate.
pub fn failure_code<'m, R: 'm, P: 'm, E: 'm>(
    matches: impl IntoIterator<Item = &'m Match<R, P, E>>,
) -> Option<ErrorCode> {
    let codes: Vec<ErrorCode> = matches.into_iter().filter_map(Match::error_code).collect();
    [
        ErrorCode::InvalidRequest,
        ErrorCode::VpFormatsNotSupported,
        ErrorCode::AccessDenied,
    ]
    .into_iter()
    .find(|code| codes.contains(code))
}
