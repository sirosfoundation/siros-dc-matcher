//! Why a plan, a selection or a response failed. Each error has a stable code and the
//! OpenID4VP 1.0, Section 8.5 code the verifier receives.

use std::fmt;

use siros_dcql::PathError;
use siros_display::DisplayError;
use siros_mdoc::DisclosureError;
use siros_oid4vp::{ErrorCode, ResponseError};
use siros_sdjwt::KeyBindingError;
use siros_transaction_data::TransactionDataError;
use siros_zkp_req_nym_auth::presenter::ProveError;

use crate::plan::NoSeed;

/// Why the core gives no plan, no chosen offer or no response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentationError {
    /// The wallet has no offer for the request. The code is the one `zkp_req.md`, Section 5
    /// gives the request.
    NoOffer(ErrorCode),
    /// An entry of `transaction_data`, or its binding to an offer, breaks a rule. The code is
    /// its own.
    TransactionData(TransactionDataError),
    /// The consent view cannot show a credential. The code is the display's.
    Display(DisplayError),
    /// The selection's plan digest is not 32 bytes of unpadded base64url.
    DigestMalformed,
    /// The selection was made on another plan (A4).
    DigestMismatch,
    /// The selection names an offer the plan lacks (A4).
    OfferUnknown,
    /// The selection names an addition the offer lacks (A4).
    AdditionUnknown,
    /// The selection names an addition twice, or two additions that answer one Credential
    /// Query (A4).
    AdditionConflict,
    /// The selection names a subset for no member of a `multiple` query of the chosen offer
    /// (A3).
    SubsetUnknown,
    /// The selection names two subsets for one member (A3).
    SubsetRepeated,
    /// A subset is empty (A3).
    SubsetEmpty,
    /// A subset names a position out of the member's credentials, or one twice (A3).
    SubsetOutOfRange,
    /// A subset drops a credential a transaction entry is bound to (T4).
    SubsetDropsEntry,
    /// A fulfilment without the wallet's UI chose an offer that needs it (A9).
    WalletDisplayNeeded,
    /// A member's credential names no key pair.
    KeyMissing,
    /// The host reported no authentication factors for a key whose KB-JWT carries `amr` (H3).
    KeyFactorsMissing,
    /// The time is before 1970-01-01T00:00:00Z, which `iat` cannot carry.
    Time,
    /// The request names its audience neither by an origin nor by a Client Identifier.
    AudienceMissing,
    /// A member's answer does not fit its credential.
    AnswerMismatch,
    /// A claims path pointer of the plan selects nothing. The code is its own.
    Pointer(PathError),
    /// The KB-JWT claims collide (S4). The code is its own.
    KeyBinding(KeyBindingError),
    /// The mdoc elements are no disclosure (M2, M3). The code is its own.
    Disclosure(DisclosureError),
    /// The nym_auth proof failed, or its credential no longer passes its tests. The code is
    /// its own.
    Prove(ProveError),
    /// The issuer delivered no usable `secret_seed` with a nym_auth credential. The code is its
    /// own.
    Seed(NoSeed),
    /// No signature answers a `Sign` effect (A5).
    SignatureMissing,
    /// Two signatures answer one `Sign` effect (A5).
    SignatureRepeated,
    /// A signature answers no `Sign` effect (A5).
    SignatureUnknown,
    /// A signature is not 64 bytes, `r ‖ s`.
    SignatureLength,
    /// A signature does not verify under the key its `Sign` effect names (A5).
    SignatureInvalid,
    /// The `vp_token` or its submission could not be built. The code is its own.
    Response(ResponseError),
}

impl PresentationError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoOffer(_) => "no_offer",
            Self::TransactionData(e) => e.code(),
            Self::Display(e) => e.code(),
            Self::DigestMalformed => "selection_digest_malformed",
            Self::DigestMismatch => "selection_digest_mismatch",
            Self::OfferUnknown => "selection_offer_unknown",
            Self::AdditionUnknown => "selection_addition_unknown",
            Self::AdditionConflict => "selection_addition_conflict",
            Self::SubsetUnknown => "selection_subset_unknown",
            Self::SubsetRepeated => "selection_subset_repeated",
            Self::SubsetEmpty => "selection_subset_empty",
            Self::SubsetOutOfRange => "selection_subset_out_of_range",
            Self::SubsetDropsEntry => "selection_subset_drops_entry",
            Self::WalletDisplayNeeded => "wallet_display_needed",
            Self::KeyMissing => "key_missing",
            Self::KeyFactorsMissing => "key_factors_missing",
            Self::Time => "time_before_epoch",
            Self::AudienceMissing => "audience_missing",
            Self::AnswerMismatch => "answer_mismatch",
            Self::Pointer(e) => e.code(),
            Self::KeyBinding(e) => e.code(),
            Self::Disclosure(e) => e.code(),
            Self::Prove(e) => e.code(),
            Self::Seed(e) => e.code(),
            Self::SignatureMissing => "signature_missing",
            Self::SignatureRepeated => "signature_repeated",
            Self::SignatureUnknown => "signature_unknown",
            Self::SignatureLength => "signature_length",
            Self::SignatureInvalid => "signature_invalid",
            Self::Response(e) => e.code(),
        }
    }

    /// The error the verifier receives (Section 8.5): the request's own code for
    /// [`PresentationError::NoOffer`], `invalid_transaction_data` for transaction data,
    /// `invalid_request` for a nym_auth query that breaks a rule, and `access_denied` for every
    /// failure of the wallet, as `zkp_req.md`, Section 5 sends one.
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NoOffer(code) => *code,
            Self::TransactionData(e) => e.error_code(),
            Self::Prove(e) => match e.error_code() {
                siros_zkp_req::ErrorCode::InvalidRequest => ErrorCode::InvalidRequest,
                _ => ErrorCode::AccessDenied,
            },
            _ => ErrorCode::AccessDenied,
        }
    }
}

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PresentationError {}
