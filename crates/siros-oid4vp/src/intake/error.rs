//! Why intake refused a request.

use std::fmt;

use crate::client_id::ClientIdError;
use crate::error_code::ErrorCode;

/// A rule of OpenID4VP 1.0 (or of RFC 9101, RFC 7515, RFC 5280) that a request breaks, or a
/// host answer that does not fit the effect it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntakeError {
    /// The authorization request URI has no query of form-encoded parameters, each once.
    NotAnAuthorizationRequest,
    /// `client_id` is missing or not a string (Section 5.2; A.2 for signed DC API requests).
    ClientIdMissing,
    /// Both `request` and `request_uri` are present (RFC 9101, Section 5).
    RequestAndRequestUri,
    /// `request_uri_method` is present without `request_uri` (Section 5.1).
    RequestUriMethodWithoutRequestUri,
    /// `request_uri_method` is neither `get` nor `post` (Section 5.1).
    RequestUriMethodInvalid,
    /// `request_uri` is not an `https` URL (H1).
    RequestUriNotHttps,
    /// The Request URI answered with a status other than 200 (Section 5.10.2).
    FetchStatus,
    /// The Request URI answered with a media type other than `application/oauth-authz-req+jwt`
    /// (Section 5.10.1; RFC 9101, Section 10.4.1).
    FetchContentType,
    /// The Request URI answered with more bytes than the fetch allowed.
    FetchTooLarge,
    /// A JWS is not three base64url segments with a JSON object header and a 64-byte signature.
    JwsMalformed,
    /// The JWS `alg` is not `ES256`.
    AlgorithmUnsupported,
    /// The JWS header has `crit` (RFC 7515, Section 4.1.11).
    CriticalHeader,
    /// The Request Object's `typ` is not `oauth-authz-req+jwt` (Section 5).
    TypMismatch,
    /// The signature does not verify under the key its Client Identifier Prefix names.
    SignatureInvalid,
    /// The Request Object is not a JSON object.
    RequestObjectNotObject,
    /// The Request Object holds `request` or `request_uri` (RFC 9101, Section 4).
    NestedRequest,
    /// The `client_id` parameter and the Request Object's `client_id` differ (Section 5.10.1).
    ClientIdMismatch,
    /// The Request Object does not echo the `wallet_nonce` the wallet posted (Section 5.10.1).
    WalletNonceMismatch,
    /// The `client_id` is not one this wallet supports (Section 5.9).
    ClientId(ClientIdError),
    /// A signed request uses the `redirect_uri` prefix (Section 5.9.3).
    SignedRedirectUri,
    /// An unsigned request uses a prefix other than `redirect_uri` (Section 5.9.3).
    UnsignedNeedsRedirectUri,
    /// `x5c` is missing, not base64 DER, or its leaf has no P-256 key.
    CertificateChainInvalid,
    /// No dNSName SAN of the leaf certificate is the `x509_san_dns` value.
    SanMismatch,
    /// The SHA-256 of the leaf certificate is not the `x509_hash` value.
    CertificateHashMismatch,
    /// `kid` does not name a key of the `decentralized_identifier` DID.
    KidNotOfClient,
    /// The host's trust answer carries no P-256 JWK for a key it was asked to resolve.
    KeyNotResolved,
    /// The `jwt` Header Parameter is not a Verifier Attestation JWT (Section 12).
    AttestationInvalid,
    /// The attestation's `sub` is not the `verifier_attestation` value.
    AttestationSubjectMismatch,
    /// The attestation's `exp` has passed, or its `nbf` has not come.
    AttestationExpired,
    /// The attestation's signature does not verify under its issuer's key.
    AttestationSignatureInvalid,
    /// The Response URI is not among the attestation's `redirect_uris`.
    RedirectUriNotAttested,
    /// An `openid4vp-v1-multisigned` payload holds `client_id` (A.3.2.2).
    ClientIdInPayload,
    /// No signature of an `openid4vp-v1-multisigned` request verifies.
    NoVerifiableSignature,
    /// The DC API request has no entry this wallet reads.
    EnvelopeUnreadable,
    /// A signed DC API request has no non-empty `expected_origins` of strings (A.2).
    ExpectedOriginsMissing,
    /// The calling origin is not in `expected_origins` (A.2).
    OriginNotExpected,
    /// `response_type` is not `vp_token` (Section 5.6).
    ResponseTypeUnsupported,
    /// `nonce` is missing, empty, or holds a character other than ASCII URL-safe ones
    /// (Section 5.2).
    NonceInvalid,
    /// `state` holds a character other than ASCII URL-safe ones (Section 5.2).
    StateInvalid,
    /// `response_mode` is missing, unknown, or of the other channel: `direct_post`,
    /// `direct_post.jwt` and `direct_post.cwt` over redirects, `dc_api` and `dc_api.jwt` over
    /// the DC API.
    ResponseModeUnsupported,
    /// A `direct_post` request has no `response_uri` (Section 8.2).
    ResponseUriMissing,
    /// `response_uri` is not an `https` URL (H1).
    ResponseUriNotHttps,
    /// A `direct_post` request also has `redirect_uri` (Section 8.2).
    RedirectUriWithDirectPost,
    /// The `response_uri` of a `redirect_uri` client is not its Client Identifier.
    ResponseUriNotClientId,
    /// The host of the `response_uri` of an untrusted `x509_san_dns` client is not its DNS
    /// name (Section 5.9.3).
    ResponseUriHostMismatch,
    /// The request uses `scope` without `dcql_query`; this wallet maps no scope to a query.
    ScopeUnsupported,
    /// The request has both `dcql_query` and `scope` (Section 5.1).
    QueryAndScope,
    /// The request has no `dcql_query` (Section 5.1).
    DcqlQueryMissing,
    /// `dcql_query` is not a DCQL query `siros-dcql` accepts.
    DcqlQueryInvalid,
    /// `client_metadata` is not a JSON object.
    ClientMetadataInvalid,
    /// `transaction_data` is not a non-empty array of strings (Section 5.1).
    TransactionDataInvalid,
    /// `verifier_info` breaks a rule of Section 5.1.
    VerifierInfo(VerifierInfoRule),
    /// An encrypted Response Mode, and no key of `jwks` is a P-256 `ECDH-ES` encryption key.
    EncryptionKeyMissing,
    /// `encrypted_response_enc_values_supported` names no `enc` of the Response Mode's
    /// envelope: `A128GCM` or `A256GCM` for a JWE, these or `A192GCM` for a `COSE_Encrypt`.
    EncryptionUnsupported,
    /// The host answered an effect with the result of the other kind.
    AnswerMismatch,
    /// The host's trust answer carries a key or metadata the subject takes none of.
    UnexpectedTrustKey,
    /// The state holds more answers than the request asked effects.
    UnusedAnswer,
}

/// A rule of `verifier_info` (Section 5.1) that a request breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifierInfoRule {
    /// `verifier_info` is not an array.
    NotArray,
    /// The array is empty.
    Empty,
    /// An attestation is not a JSON object.
    NotObject,
    /// An attestation has no string `format`.
    Format,
    /// An attestation's `data` is neither an object nor a string.
    Data,
    /// An attestation's `credential_ids` is not a non-empty array of strings.
    CredentialIds,
    /// An attestation's `credential_ids` names no Credential Query of `dcql_query`.
    CredentialIdUnknown,
}

impl VerifierInfoRule {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotArray => "verifier_info_not_array",
            Self::Empty => "verifier_info_empty",
            Self::NotObject => "verifier_info_not_object",
            Self::Format => "verifier_info_format",
            Self::Data => "verifier_info_data",
            Self::CredentialIds => "verifier_info_credential_ids",
            Self::CredentialIdUnknown => "verifier_info_credential_id_unknown",
        }
    }
}

impl IntakeError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotAnAuthorizationRequest => "not_an_authorization_request",
            Self::ClientIdMissing => "client_id_missing",
            Self::RequestAndRequestUri => "request_and_request_uri",
            Self::RequestUriMethodWithoutRequestUri => "request_uri_method_without_request_uri",
            Self::RequestUriMethodInvalid => "request_uri_method_invalid",
            Self::RequestUriNotHttps => "request_uri_not_https",
            Self::FetchStatus => "fetch_status",
            Self::FetchContentType => "fetch_content_type",
            Self::FetchTooLarge => "fetch_too_large",
            Self::JwsMalformed => "jws_malformed",
            Self::AlgorithmUnsupported => "algorithm_unsupported",
            Self::CriticalHeader => "critical_header",
            Self::TypMismatch => "typ_mismatch",
            Self::SignatureInvalid => "signature_invalid",
            Self::RequestObjectNotObject => "request_object_not_object",
            Self::NestedRequest => "nested_request",
            Self::ClientIdMismatch => "client_id_mismatch",
            Self::WalletNonceMismatch => "wallet_nonce_mismatch",
            Self::ClientId(e) => e.code(),
            Self::SignedRedirectUri => "signed_redirect_uri",
            Self::UnsignedNeedsRedirectUri => "unsigned_needs_redirect_uri",
            Self::CertificateChainInvalid => "certificate_chain_invalid",
            Self::SanMismatch => "san_mismatch",
            Self::CertificateHashMismatch => "certificate_hash_mismatch",
            Self::KidNotOfClient => "kid_not_of_client",
            Self::KeyNotResolved => "key_not_resolved",
            Self::AttestationInvalid => "attestation_invalid",
            Self::AttestationSubjectMismatch => "attestation_subject_mismatch",
            Self::AttestationExpired => "attestation_expired",
            Self::AttestationSignatureInvalid => "attestation_signature_invalid",
            Self::RedirectUriNotAttested => "redirect_uri_not_attested",
            Self::ClientIdInPayload => "client_id_in_payload",
            Self::NoVerifiableSignature => "no_verifiable_signature",
            Self::EnvelopeUnreadable => "envelope_unreadable",
            Self::ExpectedOriginsMissing => "expected_origins_missing",
            Self::OriginNotExpected => "origin_not_expected",
            Self::ResponseTypeUnsupported => "response_type_unsupported",
            Self::NonceInvalid => "nonce_invalid",
            Self::StateInvalid => "state_invalid",
            Self::ResponseModeUnsupported => "response_mode_unsupported",
            Self::ResponseUriMissing => "response_uri_missing",
            Self::ResponseUriNotHttps => "response_uri_not_https",
            Self::RedirectUriWithDirectPost => "redirect_uri_with_direct_post",
            Self::ResponseUriNotClientId => "response_uri_not_client_id",
            Self::ResponseUriHostMismatch => "response_uri_host_mismatch",
            Self::ScopeUnsupported => "scope_unsupported",
            Self::QueryAndScope => "query_and_scope",
            Self::DcqlQueryMissing => "dcql_query_missing",
            Self::DcqlQueryInvalid => "dcql_query_invalid",
            Self::ClientMetadataInvalid => "client_metadata_invalid",
            Self::TransactionDataInvalid => "transaction_data_invalid",
            Self::VerifierInfo(rule) => rule.code(),
            Self::EncryptionKeyMissing => "encryption_key_missing",
            Self::EncryptionUnsupported => "encryption_unsupported",
            Self::AnswerMismatch => "answer_mismatch",
            Self::UnexpectedTrustKey => "unexpected_trust_key",
            Self::UnusedAnswer => "unused_answer",
        }
    }

    /// The error code of OpenID4VP 1.0, Section 8.5, a Verifier receives for this refusal.
    #[must_use]
    pub fn error_code(self) -> ErrorCode {
        match self {
            Self::RequestUriMethodInvalid => ErrorCode::InvalidRequestUriMethod,
            Self::ScopeUnsupported => ErrorCode::InvalidScope,
            Self::NotAnAuthorizationRequest
            | Self::ClientIdMissing
            | Self::RequestAndRequestUri
            | Self::RequestUriMethodWithoutRequestUri
            | Self::RequestUriNotHttps
            | Self::FetchStatus
            | Self::FetchContentType
            | Self::FetchTooLarge
            | Self::JwsMalformed
            | Self::AlgorithmUnsupported
            | Self::CriticalHeader
            | Self::TypMismatch
            | Self::SignatureInvalid
            | Self::RequestObjectNotObject
            | Self::NestedRequest
            | Self::ClientIdMismatch
            | Self::WalletNonceMismatch
            | Self::ClientId(_)
            | Self::SignedRedirectUri
            | Self::UnsignedNeedsRedirectUri
            | Self::CertificateChainInvalid
            | Self::SanMismatch
            | Self::CertificateHashMismatch
            | Self::KidNotOfClient
            | Self::KeyNotResolved
            | Self::AttestationInvalid
            | Self::AttestationSubjectMismatch
            | Self::AttestationExpired
            | Self::AttestationSignatureInvalid
            | Self::RedirectUriNotAttested
            | Self::ClientIdInPayload
            | Self::NoVerifiableSignature
            | Self::EnvelopeUnreadable
            | Self::ExpectedOriginsMissing
            | Self::OriginNotExpected
            | Self::ResponseTypeUnsupported
            | Self::NonceInvalid
            | Self::StateInvalid
            | Self::ResponseModeUnsupported
            | Self::ResponseUriMissing
            | Self::ResponseUriNotHttps
            | Self::RedirectUriWithDirectPost
            | Self::ResponseUriNotClientId
            | Self::ResponseUriHostMismatch
            | Self::QueryAndScope
            | Self::DcqlQueryMissing
            | Self::DcqlQueryInvalid
            | Self::ClientMetadataInvalid
            | Self::TransactionDataInvalid
            | Self::VerifierInfo(_)
            | Self::EncryptionKeyMissing
            | Self::EncryptionUnsupported
            | Self::AnswerMismatch
            | Self::UnexpectedTrustKey
            | Self::UnusedAnswer => ErrorCode::InvalidRequest,
        }
    }
}

impl From<ClientIdError> for IntakeError {
    fn from(error: ClientIdError) -> Self {
        Self::ClientId(error)
    }
}

impl From<VerifierInfoRule> for IntakeError {
    fn from(rule: VerifierInfoRule) -> Self {
        Self::VerifierInfo(rule)
    }
}

impl fmt::Display for IntakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for IntakeError {}
