//! The request intake verified (P1).

use p256::PublicKey;
use serde_json::Value;
use siros_dcql::DcqlQuery;

use crate::client_id::ClientId;
use crate::fetch::HttpsUrl;
use crate::handover::Handover;
use crate::protocol::Protocol;

/// An OpenID4VP request that intake verified. Only intake constructs it.
///
/// Its existence guarantees P1:
/// - the Request Object's signature verifies under the rule of its Client Identifier Prefix;
///   a `redirect_uri` client's request is unsigned, and its Response URI is its identifier;
/// - the `client_id` parameter and the Request Object's `client_id` are equal;
/// - the host gave a trust verdict for the Client Identifier, or for the origin of an
///   unsigned DC API request;
/// - `nonce` is present;
/// - the Response Mode belongs to the channel: `direct_post`, `direct_post.jwt` or
///   `direct_post.cwt` over redirects, `dc_api` or `dc_api.jwt` over the DC API;
/// - a redirect response has a `response_uri`;
/// - a signed DC API request lists the calling origin in `expected_origins`;
/// - an encrypted Response Mode has a chosen key and `enc`;
/// - for `openid4vp-v1-multisigned`, the Client Identifier is that of the first signature that
///   verifies and is trusted, or of the first that verifies when none is trusted;
/// - an `x509_san_dns` or `x509_hash` client's access certificate is the leaf that signed;
/// - `verifier_info` is a non-empty array of objects with a string `format`, a `data` object or
///   string, and `credential_ids` naming Credential Queries when present (Section 5.1).
#[derive(Debug, Clone)]
pub struct VerifiedRequest {
    pub(crate) channel: Channel,
    pub(crate) trusted: bool,
    pub(crate) access_certificate: Option<AccessCertificate>,
    pub(crate) verifier_info: Vec<String>,
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
    /// Redirects: the response is posted to `response_uri` in `encoding`.
    Redirect {
        client_id: ClientId,
        response_uri: HttpsUrl,
        encoding: PostEncoding,
    },
    /// The DC API: the platform returns the response to `origin`, encrypted for `dc_api.jwt`.
    /// `client_id` is `None` for an unsigned request.
    DcApi {
        protocol: Protocol,
        client_id: Option<ClientId>,
        origin: String,
        encryption: Option<Encryption>,
    },
}

/// The body of a redirect response.
#[derive(Debug, Clone)]
pub(crate) enum PostEncoding {
    /// `direct_post`: form parameters.
    Form,
    /// `direct_post.jwt`: the form parameter `response`, a JWE.
    Jwe(Encryption),
    /// `direct_post.cwt`: a `COSE_Encrypt` (`zkp_req.md`, Section 6.2).
    Cose(Encryption),
}

/// The Response Mode of a verified request (Sections 8.2, 8.3.1; A.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseMode {
    /// `direct_post`.
    DirectPost,
    /// `direct_post.jwt`.
    DirectPostJwt,
    /// `direct_post.cwt` (`zkp_req.md`, Section 6.2).
    DirectPostCwt,
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
            Self::DirectPostCwt => "direct_post.cwt",
            Self::DcApi => "dc_api",
            Self::DcApiJwt => "dc_api.jwt",
        }
    }
}

/// The content encryption of an encrypted response: AES GCM with a 96-bit IV and a 128-bit tag
/// (RFC 7518, Section 5.3; RFC 9053, Section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncryption {
    /// `A128GCM`.
    A128Gcm,
    /// `A192GCM`, for `direct_post.cwt` only.
    A192Gcm,
    /// `A256GCM`.
    A256Gcm,
}

impl ContentEncryption {
    /// What a JWE uses (Section 8.3).
    pub(crate) const JWE: [Self; 2] = [Self::A128Gcm, Self::A256Gcm];

    /// What a `COSE_Encrypt` uses (`zkp_req.md`, Section 6.2).
    pub(crate) const COSE: [Self; 3] = [Self::A128Gcm, Self::A192Gcm, Self::A256Gcm];

    /// The name in `encrypted_response_enc_values_supported` and in the JWE `enc`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    /// The COSE algorithm value (RFC 9053, Section 4.1).
    pub(crate) fn cose_alg(self) -> u64 {
        match self {
            Self::A128Gcm => 1,
            Self::A192Gcm => 2,
            Self::A256Gcm => 3,
        }
    }

    /// The key length in bits.
    pub(crate) fn key_bits(self) -> u32 {
        match self {
            Self::A128Gcm => 128,
            Self::A192Gcm => 192,
            Self::A256Gcm => 256,
        }
    }

    /// The key length in bytes.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A192Gcm => 24,
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

/// The certificate a Wallet-Relying Party signed its Request Object with under an `x509_san_dns`
/// or `x509_hash` Client Identifier: its access certificate (ETSI TS 119 475, Clause 4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCertificate {
    pub(crate) der: Vec<u8>,
    pub(crate) semantic_identifier: Option<String>,
}

impl AccessCertificate {
    /// The certificate, DER.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The Wallet-Relying Party's semantic identifier: its `organizationIdentifier`, or for a
    /// natural person its `serialNumber`, in the structure of ETSI EN 319 412-1, Clause 5.1.4 or
    /// 5.1.3 (ETSI TS 119 475, Clauses 5.1.3 and 5.1.5), such as `VATBE-0876866142`. `None` when
    /// the subject holds no such attribute.
    #[must_use]
    pub fn semantic_identifier(&self) -> Option<&str> {
        self.semantic_identifier.as_deref()
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
                ..
            } => (None, origin.as_str()),
        };
        VerifierView {
            client_id,
            trusted: self.trusted,
            display,
        }
    }

    /// The protocol a DC API request arrived under (A.1).
    #[must_use]
    pub fn dc_api_protocol(&self) -> Option<Protocol> {
        match &self.channel {
            Channel::DcApi { protocol, .. } => Some(*protocol),
            Channel::Redirect { .. } => None,
        }
    }

    /// The access certificate of an `x509_san_dns` or `x509_hash` client.
    #[must_use]
    pub fn access_certificate(&self) -> Option<&AccessCertificate> {
        self.access_certificate.as_ref()
    }

    /// The `format` of each `verifier_info` attestation, in the request's order (Section 5.1).
    #[must_use]
    pub fn verifier_info_formats(&self) -> &[String] {
        &self.verifier_info
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
        match &self.channel {
            Channel::Redirect { encoding, .. } => match encoding {
                PostEncoding::Form => ResponseMode::DirectPost,
                PostEncoding::Jwe(_) => ResponseMode::DirectPostJwt,
                PostEncoding::Cose(_) => ResponseMode::DirectPostCwt,
            },
            Channel::DcApi { encryption, .. } => match encryption {
                None => ResponseMode::DcApi,
                Some(_) => ResponseMode::DcApiJwt,
            },
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
        match &self.channel {
            Channel::Redirect { encoding, .. } => match encoding {
                PostEncoding::Form => None,
                PostEncoding::Jwe(encryption) | PostEncoding::Cose(encryption) => Some(encryption),
            },
            Channel::DcApi { encryption, .. } => encryption.as_ref(),
        }
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
        let thumbprint = self.encryption().map(|e| &e.thumbprint);
        match &self.channel {
            Channel::Redirect {
                client_id,
                response_uri,
                ..
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
