//! Why a plan failed. Each error has a stable code and the OpenID4VP 1.0, Section 8.5 code the
//! verifier receives.

use siros_display::DisplayError;
use siros_oid4vp::ErrorCode;
use siros_transaction_data::TransactionDataError;
use siros_trust::{ChainRefusal, Unadmitted};

use crate::inconsistency::Inconsistency;
use crate::matching::{ChoiceError, Failure};
use crate::plan::Unproven;

/// Why the core gives no plan.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum PresentationError {
    /// The wallet has no offer for the request, and why.
    NoOffer(#[from] Failure<Unadmitted<ChainRefusal>, Unproven>),
    /// An entry of `transaction_data`, or its binding to an offer, breaks a rule. The code is
    /// its own.
    TransactionData(#[from] TransactionDataError),
    /// The consent view cannot show a credential. The code is the display's.
    Display(#[from] DisplayError),
    /// The plan contradicts the matching it was built from.
    Inconsistent(#[from] Inconsistency),
    /// A proof choice gives no option or usable pair of its query.
    Choice(#[from] ChoiceError),
}

impl PresentationError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoOffer(failure) => failure.code(),
            Self::TransactionData(e) => e.code(),
            Self::Display(e) => e.code(),
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
            Self::NoOffer(failure) => oid4vp_code(failure.error_code()),
            Self::TransactionData(e) => e.error_code(),
            Self::Display(_) | Self::Inconsistent(_) | Self::Choice(_) => ErrorCode::AccessDenied,
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
