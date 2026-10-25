//! Outcomes and error codes (`zkp_req`, Section 5), and the request rules of this document.

use std::fmt;

/// The error code a Wallet sends for a Credential Query it cannot answer (Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The query breaks a rule of `zkp_req` or of the function catalogue.
    InvalidRequest,
    /// The Wallet has no usable pair for any option of the query (Section 1.3).
    VpFormatsNotSupported,
    /// No credential can answer, the User declines, or proving fails. Sent without
    /// `error_description`.
    AccessDenied,
}

impl ErrorCode {
    /// The code as OpenID4VP 1.0, Section 8.5 writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::VpFormatsNotSupported => "vp_formats_not_supported",
            Self::AccessDenied => "access_denied",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rule of `zkp_req` that a request breaks. Each one makes the request invalid
/// ([`ErrorCode::InvalidRequest`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestRule {
    /// The Credential Query is not a JSON object.
    QueryNotObject,
    /// `id` is missing, empty or not a string (OpenID4VP 1.0, Section 6.1).
    QueryIdInvalid,
    /// `format` is not `zkp_req`.
    FormatNotZkpReq,
    /// `claims` is present (Section 1.1).
    ClaimsPresent,
    /// `claim_sets` is present (Section 1.1).
    ClaimSetsPresent,
    /// `meta` is missing or not an object (Section 1.1).
    MetaInvalid,
    /// `meta.source_format` is missing, empty or not a string (Section 1.1).
    SourceFormatInvalid,
    /// The `meta` member the source format defines is missing or malformed (Section 1.1).
    TypeValueInvalid,
    /// `_req` is missing, not an array or empty (Section 2).
    ReqInvalid,
    /// A `_req` item is not an object (Section 2).
    ItemNotObject {
        /// The item's index.
        item: usize,
    },
    /// A `_req` item has a member other than `fn_id`, `params` and `return` (Section 2).
    ItemMemberUnknown {
        /// The item's index.
        item: usize,
    },
    /// `fn_id` is missing, empty or not a string (Section 2).
    FnIdInvalid {
        /// The item's index.
        item: usize,
    },
    /// `params` is not an object (Section 2).
    ParamsNotObject {
        /// The item's index.
        item: usize,
    },
    /// `return` is not a non-empty string of ASCII letters, digits, `_` and `-` (Section 2).
    ReturnInvalid {
        /// The item's index.
        item: usize,
    },
    /// `return` repeats the handle of an earlier item (Section 2).
    ReturnRepeated {
        /// The index of the item that repeats it.
        item: usize,
    },
    /// `_req_sets` is not a non-empty array (Section 2.1).
    ReqSetsInvalid,
    /// An option is not a non-empty array of `_req` indexes, each at most once (Section 2.1).
    OptionInvalid {
        /// The option's index.
        option: usize,
    },
    /// `trusted_authorities` is malformed (OpenID4VP 1.0, Section 6.1.1).
    TrustedAuthoritiesInvalid,
    /// `require_cryptographic_holder_binding` is not a boolean (OpenID4VP 1.0, Section 6.1).
    HolderBindingInvalid,
    /// `client_metadata` has no `vp_formats_supported.zkp_req` object (Section 1.2).
    FormatsMissing,
    /// `proof_backend_values` is not a non-empty array of strings (Section 1.2).
    ProofBackendValuesInvalid,
    /// `system_id_values` is not a non-empty array of strings (Section 1.2).
    SystemIdValuesInvalid,
}

impl RequestRule {
    /// A stable identifier of the rule, shared with the conformance vectors.
    pub fn code(&self) -> &'static str {
        match self {
            Self::QueryNotObject => "query_not_object",
            Self::QueryIdInvalid => "query_id_invalid",
            Self::FormatNotZkpReq => "format_not_zkp_req",
            Self::ClaimsPresent => "claims_present",
            Self::ClaimSetsPresent => "claim_sets_present",
            Self::MetaInvalid => "meta_invalid",
            Self::SourceFormatInvalid => "source_format_invalid",
            Self::TypeValueInvalid => "type_value_invalid",
            Self::ReqInvalid => "req_invalid",
            Self::ItemNotObject { .. } => "item_not_object",
            Self::ItemMemberUnknown { .. } => "item_member_unknown",
            Self::FnIdInvalid { .. } => "fn_id_invalid",
            Self::ParamsNotObject { .. } => "params_not_object",
            Self::ReturnInvalid { .. } => "return_invalid",
            Self::ReturnRepeated { .. } => "return_repeated",
            Self::ReqSetsInvalid => "req_sets_invalid",
            Self::OptionInvalid { .. } => "option_invalid",
            Self::TrustedAuthoritiesInvalid => "trusted_authorities_invalid",
            Self::HolderBindingInvalid => "holder_binding_invalid",
            Self::FormatsMissing => "formats_missing",
            Self::ProofBackendValuesInvalid => "proof_backend_values_invalid",
            Self::SystemIdValuesInvalid => "system_id_values_invalid",
        }
    }
}

impl fmt::Display for RequestRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for RequestRule {}
