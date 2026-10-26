//! The request parameters of an authenticated request, read into a [`VerifiedRequest`]
//! (OpenID4VP 1.0, Sections 5.1, 5.2, 8.2, 8.3; A.2).

use serde_json::{Map, Value};
use siros_dcql::DcqlQuery;

use super::signature::{strings, Metadata, UriRule, Verifier};
use super::IntakeError;
use crate::client_id::ClientId;
use crate::fetch::HttpsUrl;
use crate::handover::ec_jwk_thumbprint;
use crate::jose;
use crate::verified::{Channel, ContentEncryption, Encryption, PostEncoding, VerifiedRequest};

/// The channel a request arrived on, and who sent it.
pub(super) enum Arrival<'a> {
    /// Redirects.
    Redirect(Verifier),
    /// A signed DC API request from `origin`.
    DcApiSigned { origin: &'a str, verifier: Verifier },
    /// An unsigned DC API request from `origin`, with the host's verdict on the origin.
    DcApiUnsigned { origin: &'a str, trusted: bool },
}

/// The verified request that arrived as `arrival`, from its request parameters `params`.
pub(super) fn verified(
    params: &Map<String, Value>,
    arrival: Arrival<'_>,
) -> Result<VerifiedRequest, IntakeError> {
    let text = |name: &str| params.get(name).and_then(Value::as_str);
    // RFC 9101, Section 4: no Request Object nested in a Request Object.
    if params.contains_key("request") || params.contains_key("request_uri") {
        return Err(IntakeError::NestedRequest);
    }
    if text("response_type") != Some("vp_token") {
        return Err(IntakeError::ResponseTypeUnsupported);
    }
    let nonce = text("nonce")
        .filter(|n| url_safe(n))
        .ok_or(IntakeError::NonceInvalid)?
        .to_owned();
    let state = match params.get("state") {
        None => None,
        Some(state) => Some(
            state
                .as_str()
                .filter(|s| url_safe(s))
                .ok_or(IntakeError::StateInvalid)?
                .to_owned(),
        ),
    };
    let mode = text("response_mode");
    let (target, trusted, metadata) = match arrival {
        Arrival::Redirect(verifier) => {
            let encoding = match mode {
                Some("direct_post") => Encoding::Form,
                Some("direct_post.jwt") => Encoding::Jwe,
                Some("direct_post.cwt") => Encoding::Cose,
                _ => return Err(IntakeError::ResponseModeUnsupported),
            };
            let target = Target::Redirect {
                response_uri: response_uri(params, &verifier.response_uri)?,
                client_id: verifier.client_id,
                encoding,
            };
            (target, verifier.trusted, verifier.metadata)
        }
        Arrival::DcApiSigned { origin, verifier } => {
            let encrypted = dc_api_encrypted(mode)?;
            let expected = params
                .get("expected_origins")
                .and_then(strings)
                .filter(|origins| !origins.is_empty())
                .ok_or(IntakeError::ExpectedOriginsMissing)?;
            if !expected.iter().any(|o| o == origin) {
                return Err(IntakeError::OriginNotExpected);
            }
            let target = Target::DcApi {
                client_id: Some(verifier.client_id),
                origin,
                encrypted,
            };
            (target, verifier.trusted, verifier.metadata)
        }
        // A.2: the Wallet ignores `client_id` and `expected_origins` of an unsigned request.
        Arrival::DcApiUnsigned { origin, trusted } => {
            let target = Target::DcApi {
                client_id: None,
                origin,
                encrypted: dc_api_encrypted(mode)?,
            };
            (target, trusted, Metadata::Request)
        }
    };
    let (dcql_query, dcql_query_json) = dcql_query(params)?;
    let client_metadata = match metadata {
        Metadata::Request => match params.get("client_metadata") {
            None => None,
            Some(metadata @ Value::Object(_)) => Some(metadata.clone()),
            Some(_) => return Err(IntakeError::ClientMetadataInvalid),
        },
        Metadata::TrustChain(metadata) => metadata,
    };
    let transaction_data = match params.get("transaction_data") {
        None => Vec::new(),
        Some(entries) => strings(entries)
            .filter(|e| !e.is_empty())
            .ok_or(IntakeError::TransactionDataInvalid)?,
    };
    let metadata = client_metadata.as_ref();
    let channel = match target {
        Target::Redirect {
            client_id,
            response_uri,
            encoding,
        } => Channel::Redirect {
            client_id,
            response_uri,
            encoding: match encoding {
                Encoding::Form => PostEncoding::Form,
                Encoding::Jwe => PostEncoding::Jwe(encryption(metadata, &ContentEncryption::JWE)?),
                Encoding::Cose => {
                    PostEncoding::Cose(encryption(metadata, &ContentEncryption::COSE)?)
                }
            },
        },
        Target::DcApi {
            client_id,
            origin,
            encrypted,
        } => Channel::DcApi {
            client_id,
            origin: origin.to_owned(),
            encryption: match encrypted {
                false => None,
                true => Some(encryption(metadata, &ContentEncryption::JWE)?),
            },
        },
    };
    Ok(VerifiedRequest {
        channel,
        trusted,
        nonce,
        state,
        dcql_query,
        dcql_query_json,
        client_metadata,
        transaction_data,
    })
}

/// Where the response goes, before its encryption is chosen.
enum Target<'a> {
    Redirect {
        client_id: ClientId,
        response_uri: HttpsUrl,
        encoding: Encoding,
    },
    DcApi {
        client_id: Option<ClientId>,
        origin: &'a str,
        encrypted: bool,
    },
}

/// The body a redirect Response Mode names.
enum Encoding {
    Form,
    Jwe,
    Cose,
}

/// Whether a DC API Response Mode encrypts: `dc_api.jwt` does, `dc_api` does not (A.2).
fn dc_api_encrypted(mode: Option<&str>) -> Result<bool, IntakeError> {
    match mode {
        Some("dc_api") => Ok(false),
        Some("dc_api.jwt") => Ok(true),
        _ => Err(IntakeError::ResponseModeUnsupported),
    }
}

/// ASCII URL-safe characters only, at least one (Section 5.2).
fn url_safe(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// The `response_uri` of a redirect request under `rule` (Section 8.2).
fn response_uri(params: &Map<String, Value>, rule: &UriRule) -> Result<HttpsUrl, IntakeError> {
    if params.contains_key("redirect_uri") {
        return Err(IntakeError::RedirectUriWithDirectPost);
    }
    let given = params.get("response_uri").and_then(Value::as_str);
    let uri = match (rule, given) {
        // Section 5.9.3: a `redirect_uri` client may omit the Response URI it is.
        (UriRule::Equals(value), None) => value.as_str(),
        (_, Some(uri)) => uri,
        (_, None) => return Err(IntakeError::ResponseUriMissing),
    };
    let url = HttpsUrl::parse(uri).ok_or(IntakeError::ResponseUriNotHttps)?;
    match rule {
        UriRule::Any => {}
        UriRule::Equals(value) if uri != value => return Err(IntakeError::ResponseUriNotClientId),
        UriRule::Equals(_) => {}
        UriRule::Host(dns) if !url.host().eq_ignore_ascii_case(dns) => {
            return Err(IntakeError::ResponseUriHostMismatch)
        }
        UriRule::Host(_) => {}
        UriRule::OneOf(uris) if !uris.iter().any(|u| u == uri) => {
            return Err(IntakeError::RedirectUriNotAttested)
        }
        UriRule::OneOf(_) => {}
    }
    Ok(url)
}

/// `dcql_query`, parsed by `siros-dcql`, and as sent (Section 5.1).
fn dcql_query(params: &Map<String, Value>) -> Result<(DcqlQuery, Value), IntakeError> {
    match (params.get("dcql_query"), params.contains_key("scope")) {
        (Some(_), true) => Err(IntakeError::QueryAndScope),
        (None, true) => Err(IntakeError::ScopeUnsupported),
        (None, false) => Err(IntakeError::DcqlQueryMissing),
        (Some(raw), false) => {
            let query = DcqlQuery::from_json(&raw.to_string())
                .map_err(|_| IntakeError::DcqlQueryInvalid)?;
            Ok((query, raw.clone()))
        }
    }
}

/// The key and `enc` of an encrypted response, for a JWE and for a `COSE_Encrypt` alike
/// (Section 8.3; `zkp_req.md`, Section 6.2): the first key of `jwks` that is a P-256 `ECDH-ES`
/// key for encryption, and the first value of `encrypted_response_enc_values_supported` among
/// `supported`, `A128GCM` when the list is absent.
fn encryption(
    metadata: Option<&Value>,
    supported: &[ContentEncryption],
) -> Result<Encryption, IntakeError> {
    let keys = metadata
        .and_then(|m| m.get("jwks"))
        .and_then(|j| j.get("keys"))
        .and_then(Value::as_array)
        .ok_or(IntakeError::EncryptionKeyMissing)?;
    let (jwk, key) = keys
        .iter()
        .find_map(|jwk| {
            let text = |name: &str| jwk.get(name).and_then(Value::as_str);
            let usable = text("alg") == Some("ECDH-ES") && text("use").is_none_or(|u| u == "enc");
            if !usable {
                return None;
            }
            Some((jwk, jose::p256_key(jwk)?))
        })
        .ok_or(IntakeError::EncryptionKeyMissing)?;
    let thumbprint = ec_jwk_thumbprint(jwk).ok_or(IntakeError::EncryptionKeyMissing)?;
    let enc = match metadata.and_then(|m| m.get("encrypted_response_enc_values_supported")) {
        None => ContentEncryption::A128Gcm,
        Some(values) => values
            .as_array()
            .and_then(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .find_map(|v| supported.iter().copied().find(|e| e.as_str() == v))
            })
            .ok_or(IntakeError::EncryptionUnsupported)?,
    };
    Ok(Encryption {
        key,
        kid: jwk.get("kid").and_then(Value::as_str).map(str::to_owned),
        enc,
        thumbprint,
    })
}
