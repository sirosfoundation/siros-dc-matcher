//! Why transaction data is refused. Each refusal has a stable code and reaches the verifier as
//! `invalid_transaction_data` (OpenID4VP 1.0, Section 8.5).

use std::fmt;

use siros_oid4vp::ErrorCode;

/// A rule a `transaction_data` entry, the type metadata of a credential, or a caller input
/// breaks.
///
/// A member is named by its path in the entry, `payload.payee.name` for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionDataError {
    /// The entry is not base64url without padding (OpenID4VP 1.0, Sections 1.2 and 5.1).
    NotBase64url,
    /// The entry does not decode to the UTF-8 JSON text of one object (Section 5.1).
    NotJsonObject,
    /// An object repeats a member name.
    DuplicateKey,
    /// Objects and arrays nest deeper than [`MAX_DEPTH`](crate::MAX_DEPTH).
    TooDeep,
    /// A required member is absent (Section 8.5).
    MissingMember(&'static str),
    /// A member has the wrong JSON type (Section 8.5).
    WrongType(&'static str),
    /// A member has a value its type does not allow (Section 8.5).
    InvalidValue(&'static str),
    /// The entry or its payload holds a member its type does not define (Section 8.5).
    UnknownMember,
    /// `type` names no supported transaction data type (Sections 5.1 and 8.5).
    UnsupportedType,
    /// A `credential_ids` element names no Credential Query of the DCQL query (Sections 5.1
    /// and 8.5).
    UnknownCredentialId,
    /// A `credential_ids` element names a Credential Query of a format the type cannot be
    /// authorized with: EC TS12 v1.0.1 covers SD-JWT VC only (Section 1.2).
    QueryFormat,
    /// A `credential_ids` element names a Credential Query with
    /// `require_cryptographic_holder_binding: false` (OpenID4VP 1.0, B.3.3).
    HolderBindingNotRequired,
    /// `transaction_data_hashes_alg` lists no algorithm this wallet computes (B.3.3.1).
    HashAlgUnsupported,
    /// The entries bound to one credential accept no common hash algorithm (B.3.3.1).
    HashAlgConflict,
    /// The chosen offer presents no credential that authorizes the entry (Sections 5.1 and
    /// 8.5).
    CredentialUnavailable,
    /// The authentication factors cover fewer than two categories (EC TS12 v1.0.1, Section
    /// 3.6).
    AmrCategories,
    /// The credential is no SD-JWT VC, the only format with type metadata (SD-JWT VC,
    /// Section 6).
    NotSdJwtVc,
    /// The credential's `vct` is not an `https` URL, so its type metadata cannot be fetched
    /// (SD-JWT VC, Section 6.3.1).
    VctNotHttps,
    /// A metadata document's URL is not an `https` URL (H1).
    DocumentNotHttps,
    /// A metadata fetch answered with a status other than 200.
    FetchStatus,
    /// A metadata fetch answered with more bytes than the fetch allowed.
    FetchTooLarge,
    /// A metadata document is not a JSON document of the shape its specification gives.
    MetadataMalformed(&'static str),
    /// The type metadata describes another `vct` than the credential's (SD-JWT VC, Section
    /// 6.3).
    VctMismatch,
    /// A `#integrity` claim of the credential is not an integrity metadata string with an
    /// algorithm this wallet computes (SD-JWT VC, Section 7; W3C SRI, Section 3).
    IntegrityMalformed,
    /// A metadata document does not match its `#integrity` claim (SD-JWT VC, Section 7).
    IntegrityMismatch,
    /// A leaf parameter of the payload that must be shown has no localised name (EC TS12
    /// v1.0.1, Section 3.3.1).
    LabelMissing,
    /// The UI elements catalogue has no `affirmative_action_label` (EC TS12 v1.0.1, Sections
    /// 3.3.1 and 3.3.3).
    AffirmativeLabelMissing,
    /// A payload value is not display text: it holds a control, format, separator,
    /// private-use or unassigned character, or is too long ([`siros_display::DisplayText`]).
    ValueNotDisplayable,
    /// A label of the type metadata is not display text.
    LabelNotDisplayable,
}

impl TransactionDataError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotBase64url => "transaction_data_not_base64url",
            Self::NotJsonObject => "transaction_data_not_json_object",
            Self::DuplicateKey => "transaction_data_duplicate_key",
            Self::TooDeep => "transaction_data_too_deep",
            Self::MissingMember(_) => "transaction_data_member_missing",
            Self::WrongType(_) => "transaction_data_member_wrong_type",
            Self::InvalidValue(_) => "transaction_data_member_invalid",
            Self::UnknownMember => "transaction_data_member_unknown",
            Self::UnsupportedType => "transaction_data_type_unsupported",
            Self::UnknownCredentialId => "transaction_data_credential_id_unknown",
            Self::QueryFormat => "transaction_data_query_format",
            Self::HolderBindingNotRequired => "transaction_data_holder_binding_not_required",
            Self::HashAlgUnsupported => "transaction_data_hash_alg_unsupported",
            Self::HashAlgConflict => "transaction_data_hash_alg_conflict",
            Self::CredentialUnavailable => "transaction_data_credential_unavailable",
            Self::AmrCategories => "transaction_data_amr_categories",
            Self::NotSdJwtVc => "type_metadata_not_sd_jwt_vc",
            Self::VctNotHttps => "type_metadata_vct_not_https",
            Self::DocumentNotHttps => "metadata_document_not_https",
            Self::FetchStatus => "metadata_fetch_status",
            Self::FetchTooLarge => "metadata_fetch_too_large",
            Self::MetadataMalformed(_) => "metadata_malformed",
            Self::VctMismatch => "type_metadata_vct_mismatch",
            Self::IntegrityMalformed => "metadata_integrity_malformed",
            Self::IntegrityMismatch => "metadata_integrity_mismatch",
            Self::LabelMissing => "transaction_display_label_missing",
            Self::AffirmativeLabelMissing => "transaction_display_affirmative_label_missing",
            Self::ValueNotDisplayable => "transaction_display_value_refused",
            Self::LabelNotDisplayable => "transaction_display_label_refused",
        }
    }

    /// The error code of OpenID4VP 1.0, Section 8.5, a verifier receives for this refusal.
    #[must_use]
    pub fn error_code(&self) -> ErrorCode {
        ErrorCode::InvalidTransactionData
    }
}

impl fmt::Display for TransactionDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMember(member)
            | Self::WrongType(member)
            | Self::InvalidValue(member)
            | Self::MetadataMalformed(member) => write!(f, "{}: {member}", self.code()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for TransactionDataError {}
