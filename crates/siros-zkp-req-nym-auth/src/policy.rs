//! The signed-request and encrypted-response policy of nym_auth (nym_auth catalogue, "Binding"
//! and "Response confidentiality"), and the session it gives.

use std::fmt;

use serde_json::Value;

use crate::session::{ec_jwk_thumbprint, Handover};

/// The channel a request arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// The Digital Credentials API, with the origin of the calling web page.
    DcApi {
        /// The calling origin, as the platform reports it.
        origin: String,
    },
    /// Redirects, including a `request_uri` from a QR code or a link.
    Redirect,
}

/// A rule of the policy that a request breaks. Each makes the request invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyRule {
    /// The request is not signed.
    Unsigned,
    /// The Request Object is not a JSON object.
    NotObject,
    /// `client_id` is missing or not a string.
    ClientIdMissing,
    /// `nonce` is missing, empty or not a string.
    NonceMissing,
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
    pub fn code(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::NotObject => "request_object_not_object",
            Self::ClientIdMissing => "client_id_missing",
            Self::NonceMissing => "nonce_missing",
            Self::ResponseMode => "response_mode",
            Self::ResponseUriMissing => "response_uri_missing",
            Self::OriginNotExpected => "origin_not_expected",
            Self::EncryptionKeyMissing => "encryption_key_missing",
        }
    }
}

impl fmt::Display for PolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PolicyRule {}

/// The channel's own value in the `Handover`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// The calling origin, over the Digital Credentials API.
    Origin(String),
    /// `response_uri`, over redirects.
    ResponseUri(String),
}

/// A Request Object that follows the policy, read for the values the session binds.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckedRequest {
    /// `client_id`, with its Client Identifier Prefix.
    pub client_id: String,
    /// `nonce`.
    pub nonce: String,
    /// What the `Handover` binds besides `client_id` and `nonce`.
    pub endpoint: Endpoint,
    /// The keys of `client_metadata.jwks`.
    pub encryption_keys: Vec<Value>,
}

/// Checks a validated Request Object against the policy. `signed` says whether it arrived as a
/// signed Request Object; the host checks the signature and the certificate chain.
///
/// # Errors
///
/// [`PolicyRule`]: the first rule the request breaks.
pub fn check_request(
    request_object: &Value,
    signed: bool,
    channel: Channel,
) -> Result<CheckedRequest, PolicyRule> {
    if !signed {
        return Err(PolicyRule::Unsigned);
    }
    let request = request_object.as_object().ok_or(PolicyRule::NotObject)?;
    let text = |name: &str| request.get(name).and_then(Value::as_str);
    let client_id = text("client_id").ok_or(PolicyRule::ClientIdMissing)?;
    let nonce = text("nonce")
        .filter(|n| !n.is_empty())
        .ok_or(PolicyRule::NonceMissing)?;
    let endpoint = match channel {
        Channel::Redirect => {
            if !matches!(
                text("response_mode"),
                Some("direct_post.cwt" | "direct_post.jwt")
            ) {
                return Err(PolicyRule::ResponseMode);
            }
            let uri = text("response_uri").ok_or(PolicyRule::ResponseUriMissing)?;
            Endpoint::ResponseUri(uri.to_owned())
        }
        Channel::DcApi { origin } => {
            if text("response_mode") != Some("dc_api.jwt") {
                return Err(PolicyRule::ResponseMode);
            }
            let expected = request.get("expected_origins").and_then(Value::as_array);
            if !expected.is_some_and(|list| list.iter().any(|o| o.as_str() == Some(&origin))) {
                return Err(PolicyRule::OriginNotExpected);
            }
            Endpoint::Origin(origin)
        }
    };
    let encryption_keys = request
        .get("client_metadata")
        .and_then(|m| m.get("jwks"))
        .and_then(|j| j.get("keys"))
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty())
        .ok_or(PolicyRule::EncryptionKeyMissing)?
        .clone();
    Ok(CheckedRequest {
        client_id: client_id.to_owned(),
        nonce: nonce.to_owned(),
        endpoint,
        encryption_keys,
    })
}

/// The host chose an encryption key that is not one of the request's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyNotInRequest;

impl fmt::Display for KeyNotInRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the JWK thumbprint is of no key in client_metadata.jwks")
    }
}

impl std::error::Error for KeyNotInRequest {}

impl CheckedRequest {
    /// The `Handover` of this request, for the response-encryption key whose JWK SHA-256
    /// Thumbprint is `jwk_thumbprint` (OpenID4VP 1.0, Section 8.3 picks the key).
    ///
    /// # Errors
    ///
    /// [`KeyNotInRequest`] when no key of `client_metadata.jwks` has that thumbprint: the
    /// session binds only values of the validated Request Object.
    pub fn handover(&self, jwk_thumbprint: &[u8; 32]) -> Result<Handover, KeyNotInRequest> {
        let known = self
            .encryption_keys
            .iter()
            .any(|k| ec_jwk_thumbprint(k).as_ref() == Some(jwk_thumbprint));
        if !known {
            return Err(KeyNotInRequest);
        }
        Ok(match &self.endpoint {
            Endpoint::Origin(origin) => Handover::dc_api(origin, &self.nonce, jwk_thumbprint),
            Endpoint::ResponseUri(uri) => {
                Handover::redirect(&self.client_id, &self.nonce, jwk_thumbprint, uri)
            }
        })
    }
}
