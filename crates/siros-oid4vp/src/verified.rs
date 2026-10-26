//! The request intake verified (P1).

use p256::PublicKey;
use serde_json::Value;
use siros_dcql::DcqlQuery;

use crate::client_id::ClientId;
use crate::fetch::HttpsUrl;
use crate::handover::Handover;

/// An OpenID4VP request that intake verified. Only intake constructs it.
///
/// Its existence guarantees P1:
/// - the Request Object's signature verifies under the rule of its Client Identifier Prefix;
///   a `redirect_uri` client's request is unsigned, and its Response URI is its identifier;
/// - the `client_id` parameter and the Request Object's `client_id` are equal;
/// - the host gave a trust verdict for the Client Identifier, or for the origin of an
///   unsigned DC API request;
/// - `nonce` is present;
/// - the Response Mode belongs to the channel: `direct_post` or `direct_post.jwt` over
///   redirects, `dc_api` or `dc_api.jwt` over the DC API;
/// - a redirect response has a `response_uri`;
/// - a signed DC API request lists the calling origin in `expected_origins`;
/// - an encrypted Response Mode has a chosen key and `enc`;
/// - for `openid4vp-v1-multisigned`, the Client Identifier is that of the first signature that
///   verifies and is trusted, or of the first that verifies when none is trusted.
#[derive(Debug, Clone)]
pub struct VerifiedRequest {
    pub(crate) channel: Channel,
    pub(crate) encryption: Option<Encryption>,
    pub(crate) trusted: bool,
    pub(crate) nonce: String,
    pub(crate) state: Option<String>,
    pub(crate) dcql_query: DcqlQuery,
    pub(crate) dcql_query_json: Value,
    pub(crate) client_metadata: Option<Value>,
    pub(crate) transaction_data: Vec<String>,
}

/// Where the response goes, and who sent the request.
#[derive(Debug, Clone)]
pub(crate) enum Channel {
    /// Redirects: the response is posted to `response_uri`.
    Redirect {
        client_id: ClientId,
        response_uri: HttpsUrl,
    },
    /// The DC API: the platform returns the response to `origin`. `client_id` is `None` for an
    /// unsigned request.
    DcApi {
        client_id: Option<ClientId>,
        origin: String,
    },
}

/// The Response Mode of a verified request (Sections 8.2, 8.3.1; A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseMode {
    /// `direct_post`.
    DirectPost,
    /// `direct_post.jwt`.
    DirectPostJwt,
    /// `dc_api`.
    DcApi,
    /// `dc_api.jwt`.
    DcApiJwt,
}

impl ResponseMode {
    /// The `response_mode` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectPost => "direct_post",
            Self::DirectPostJwt => "direct_post.jwt",
            Self::DcApi => "dc_api",
            Self::DcApiJwt => "dc_api.jwt",
        }
    }
}

/// The JWE `enc` of an encrypted response (RFC 7518, Section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncryption {
    /// `A128GCM`.
    A128Gcm,
    /// `A256GCM`.
    A256Gcm,
}

impl ContentEncryption {
    /// The `enc` value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    /// The `enc` a value names.
    pub(crate) fn named(text: &str) -> Option<Self> {
        match text {
            "A128GCM" => Some(Self::A128Gcm),
            "A256GCM" => Some(Self::A256Gcm),
            _ => None,
        }
    }

    /// The key length in bits.
    pub(crate) fn key_bits(self) -> u32 {
        match self {
            Self::A128Gcm => 128,
            Self::A256Gcm => 256,
        }
    }

    /// The key length in bytes.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A256Gcm => 32,
        }
    }
}

/// The key and `enc` an encrypted response uses (Section 8.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encryption {
    pub(crate) key: PublicKey,
    pub(crate) kid: Option<String>,
    pub(crate) enc: ContentEncryption,
    pub(crate) thumbprint: [u8; 32],
}

impl Encryption {
    /// The `kid` of the chosen JWK, which the JWE header repeats.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The content encryption.
    #[must_use]
    pub fn enc(&self) -> ContentEncryption {
        self.enc
    }
}

/// Who asks, as the consent screen shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierView<'a> {
    client_id: Option<&'a ClientId>,
    trusted: bool,
    display: &'a str,
}

impl<'a> VerifierView<'a> {
    /// The Client Identifier; `None` for an unsigned DC API request.
    #[must_use]
    pub fn client_id(&self) -> Option<&'a ClientId> {
        self.client_id
    }

    /// The host's trust verdict on the Client Identifier, or on the origin of an unsigned DC
    /// API request.
    #[must_use]
    pub fn trusted(&self) -> bool {
        self.trusted
    }

    /// The name the trust verdict is about: the original Client Identifier, or the origin of
    /// an unsigned DC API request.
    #[must_use]
    pub fn display(&self) -> &'a str {
        self.display
    }
}

impl VerifiedRequest {
    /// The verifier.
    #[must_use]
    pub fn verifier(&self) -> VerifierView<'_> {
        let (client_id, display) = match &self.channel {
            Channel::Redirect { client_id, .. } => (Some(client_id), client_id.value()),
            Channel::DcApi {
                client_id: Some(client_id),
                ..
            } => (Some(client_id), client_id.value()),
            Channel::DcApi {
                client_id: None,
                origin,
            } => (None, origin.as_str()),
        };
        VerifierView {
            client_id,
            trusted: self.trusted,
            display,
        }
    }

    /// The calling origin of a DC API request.
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        match &self.channel {
            Channel::DcApi { origin, .. } => Some(origin),
            Channel::Redirect { .. } => None,
        }
    }

    /// The Response Mode.
    #[must_use]
    pub fn response_mode(&self) -> ResponseMode {
        match (&self.channel, self.encryption.is_some()) {
            (Channel::Redirect { .. }, false) => ResponseMode::DirectPost,
            (Channel::Redirect { .. }, true) => ResponseMode::DirectPostJwt,
            (Channel::DcApi { .. }, false) => ResponseMode::DcApi,
            (Channel::DcApi { .. }, true) => ResponseMode::DcApiJwt,
        }
    }

    /// The Response URI of a redirect request.
    #[must_use]
    pub fn response_uri(&self) -> Option<&HttpsUrl> {
        match &self.channel {
            Channel::Redirect { response_uri, .. } => Some(response_uri),
            Channel::DcApi { .. } => None,
        }
    }

    /// The response encryption of an encrypted Response Mode.
    #[must_use]
    pub fn encryption(&self) -> Option<&Encryption> {
        self.encryption.as_ref()
    }

    /// `nonce`.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// `state`, which a redirect response returns.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// `dcql_query`, as `siros-dcql` parsed it.
    #[must_use]
    pub fn dcql_query(&self) -> &DcqlQuery {
        &self.dcql_query
    }

    /// `dcql_query` as sent, from which format profiles read their own members (`zkp_req`'s
    /// `_req`, for one).
    #[must_use]
    pub fn dcql_query_json(&self) -> &Value {
        &self.dcql_query_json
    }

    /// The Verifier metadata: `client_metadata`, or for an `openid_federation` client the
    /// metadata the host resolved from its Trust Chain.
    #[must_use]
    pub fn client_metadata(&self) -> Option<&Value> {
        self.client_metadata.as_ref()
    }

    /// The `transaction_data` strings as received; empty when the request has none.
    #[must_use]
    pub fn transaction_data(&self) -> &[String] {
        &self.transaction_data
    }

    /// The mdoc `Handover` of this request (B.2.6): `OpenID4VPHandover` over redirects,
    /// `OpenID4VPDCAPIHandover` over the DC API, with the thumbprint of the encryption key or
    /// `null`.
    #[must_use]
    pub fn handover(&self) -> Handover {
        let thumbprint = self.encryption.as_ref().map(|e| &e.thumbprint);
        match &self.channel {
            Channel::Redirect {
                client_id,
                response_uri,
            } => Handover::redirect(
                client_id.as_str(),
                &self.nonce,
                thumbprint,
                response_uri.as_str(),
            ),
            Channel::DcApi { origin, .. } => Handover::dc_api(origin, &self.nonce, thumbprint),
        }
    }
}
