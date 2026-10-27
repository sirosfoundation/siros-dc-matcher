//! The rules of the signed-request and encrypted-response policy of nym_auth (nym_auth
//! catalogue, "Binding" and "Response confidentiality").

use siros_oid4vp::ClientIdError;

use crate::verifier_id::VerifierIdRule;

/// A rule of the policy that a request breaks. Each makes the request invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyRule {
    /// The request is not signed.
    Unsigned,
    /// A Digital Credentials API request arrived as `openid4vp-v1-multisigned`: the catalogue
    /// requires `openid4vp-v1-signed`.
    Multisigned,
    /// The host's trust verdict on the Client Identifier is negative: the Wallet Unit validates
    /// the Request Object's certificate chain for its Client Identifier Prefix.
    Untrusted,
    /// The Request Object is not a JSON object.
    NotObject,
    /// `client_id` is missing or no string.
    ClientIdMissing,
    /// `client_id` is no Client Identifier this wallet supports (OpenID4VP 1.0, Section 5.9).
    ClientId(ClientIdError),
    /// `nonce` is missing or no string.
    NonceMissing,
    /// `nonce` is empty or holds a character outside the ASCII URL-safe ones (OpenID4VP 1.0,
    /// Section 5.2).
    NonceMalformed,
    /// The Response Mode is not one the channel allows: `direct_post.cwt` or
    /// `direct_post.jwt` over redirects, `dc_api.jwt` over the Digital Credentials API.
    ResponseMode,
    /// A redirect request has no `response_uri`.
    ResponseUriMissing,
    /// Over the Digital Credentials API, the calling origin is not in `expected_origins`.
    OriginNotExpected,
    /// `client_metadata` carries no response-encryption key in `jwks`.
    EncryptionKeyMissing,
}

impl PolicyRule {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Multisigned => "multisigned",
            Self::Untrusted => "untrusted",
            Self::NotObject => "request_object_not_object",
            Self::ClientIdMissing => "client_id_missing",
            Self::ClientId(error) => error.code(),
            Self::NonceMissing => "nonce_missing",
            Self::NonceMalformed => "nonce_malformed",
            Self::ResponseMode => "response_mode",
            Self::ResponseUriMissing => "response_uri_missing",
            Self::OriginNotExpected => "origin_not_expected",
            Self::EncryptionKeyMissing => "encryption_key_missing",
        }
    }
}

siros_codec::display_code!(PolicyRule);

impl std::error::Error for PolicyRule {}

/// Why a verified request is no nym_auth request: a rule of the policy, or of the Verifier
/// identity. Each makes a nym_auth query invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestRefusal {
    /// A rule of the signed-request and encrypted-response policy.
    Policy(PolicyRule),
    /// A rule of the `verifier_id` of the trust framework's form.
    VerifierId(VerifierIdRule),
}

impl RequestRefusal {
    /// The rule's stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Policy(rule) => rule.code(),
            Self::VerifierId(rule) => rule.code(),
        }
    }
}

siros_codec::display_code!(RequestRefusal);

impl std::error::Error for RequestRefusal {}
