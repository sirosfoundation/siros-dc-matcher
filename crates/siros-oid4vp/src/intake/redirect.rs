//! Intake of an authorization request URI: parameters by value, a Request Object by value
//! (`request`), or by reference (`request_uri`, Section 5.10; RFC 9101, Section 5).

use rustc_hash::FxHashMap;
use serde_json::{Map, Value};

use super::request::{self, Arrival};
use super::signature::{self, by_request, UriRule};
use super::trust::{self, KeyMaterial, TrustSubject};
use super::{Answers, Halt, IntakeError};
use crate::client_id::{ClientId, ClientIdPrefix};
use crate::fetch::{Fetch, HttpsUrl, Method};
use crate::form;
use crate::jose;
use crate::verified::VerifiedRequest;

/// The media type of a Request Object (RFC 9101, Section 10.2).
const REQUEST_OBJECT_MEDIA_TYPE: &str = "application/oauth-authz-req+jwt";

/// The largest Request Object fetched, in bytes.
const MAX_REQUEST_OBJECT: usize = 256 * 1024;

/// What the wallet posts for `request_uri_method=post` (Section 5.10).
pub(super) struct Wallet<'a> {
    pub(super) vp_formats_supported: &'a Map<String, Value>,
    pub(super) nonce: &'a str,
}

/// Intake of the authorization request URI `uri`.
pub(super) fn intake(
    uri: &str,
    wallet: &Wallet<'_>,
    now_unix: u64,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let query = uri
        .split_once('?')
        .and_then(|(_, rest)| rest.split('#').next())
        .ok_or(IntakeError::NotAnAuthorizationRequest)?;
    let params = form::parse(query).ok_or(IntakeError::NotAnAuthorizationRequest)?;
    let outer = params
        .get("client_id")
        .ok_or(IntakeError::ClientIdMissing)?;
    let method = params.get("request_uri_method").map(String::as_str);
    match (params.get("request"), params.get("request_uri")) {
        (Some(_), Some(_)) => Err(IntakeError::RequestAndRequestUri.into()),
        (_, None) if method.is_some() => Err(IntakeError::RequestUriMethodWithoutRequestUri.into()),
        (Some(jws), None) => signed(jws, outer, None, now_unix, answers),
        (None, Some(request_uri)) => {
            let post = match method {
                None | Some("get") => false,
                Some("post") => true,
                Some(_) => return Err(IntakeError::RequestUriMethodInvalid.into()),
            };
            // A `redirect_uri` client cannot sign, so its Request Object is not fetched.
            if ClientId::parse(outer)?.prefix() == ClientIdPrefix::RedirectUri {
                return Err(IntakeError::SignedRedirectUri.into());
            }
            let url = HttpsUrl::parse(request_uri).ok_or(IntakeError::RequestUriNotHttps)?;
            let method = if post {
                let metadata = wallet_metadata(wallet.vp_formats_supported);
                Method::PostForm {
                    body: form::encode(&[
                        ("wallet_metadata", &metadata),
                        ("wallet_nonce", wallet.nonce),
                    ]),
                }
            } else {
                Method::Get
            };
            let fetch = Fetch::new(url, method, REQUEST_OBJECT_MEDIA_TYPE, MAX_REQUEST_OBJECT);
            let response = answers.fetch(fetch)?;
            if response.status() != 200 {
                return Err(IntakeError::FetchStatus.into());
            }
            if !response.has_media_type(REQUEST_OBJECT_MEDIA_TYPE) {
                return Err(IntakeError::FetchContentType.into());
            }
            if response.body().len() > MAX_REQUEST_OBJECT {
                return Err(IntakeError::FetchTooLarge.into());
            }
            let jws =
                std::str::from_utf8(response.body()).map_err(|_| IntakeError::JwsMalformed)?;
            let nonce = post.then_some(wallet.nonce);
            signed(jws.trim(), outer, nonce, now_unix, answers)
        }
        (None, None) => unsigned(&params, outer, answers),
    }
}

/// `wallet_metadata` (Section 10): the wallet's formats, and the Client Identifier Prefixes
/// and Request Object algorithm this core supports.
fn wallet_metadata(vp_formats_supported: &Map<String, Value>) -> String {
    serde_json::json!({
        "vp_formats_supported": vp_formats_supported,
        "client_id_prefixes_supported": ClientIdPrefix::ALL.map(ClientIdPrefix::as_str),
        "request_object_signing_alg_values_supported": ["ES256"],
    })
    .to_string()
}

/// A signed Request Object; `wallet_nonce` is the nonce the wallet posted.
fn signed(
    jws: &str,
    outer: &str,
    wallet_nonce: Option<&str>,
    now_unix: u64,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let (signed, payload) = jose::compact(jws)?;
    let Ok(Value::Object(object)) = serde_json::from_slice(&payload) else {
        return Err(IntakeError::RequestObjectNotObject.into());
    };
    let inner = object
        .get("client_id")
        .and_then(Value::as_str)
        .ok_or(IntakeError::ClientIdMissing)?;
    if inner != outer {
        return Err(IntakeError::ClientIdMismatch.into());
    }
    if let Some(nonce) = wallet_nonce {
        if object.get("wallet_nonce").and_then(Value::as_str) != Some(nonce) {
            return Err(IntakeError::WalletNonceMismatch.into());
        }
    }
    let verifier = signature::authenticate(&signed, ClientId::parse(inner)?, now_unix, answers)?;
    Ok(request::verified(&object, Arrival::Redirect(verifier))?)
}

/// Parameters by value: the request of a `redirect_uri` client.
fn unsigned(
    params: &FxHashMap<String, String>,
    client_id: &str,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let client_id = ClientId::parse(client_id)?;
    if client_id.prefix() != ClientIdPrefix::RedirectUri {
        return Err(IntakeError::UnsignedNeedsRedirectUri.into());
    }
    let mut object = Map::new();
    for (name, value) in params {
        // Section 5.1: parameters holding objects travel as JSON-serialized strings.
        let invalid = match name.as_str() {
            "dcql_query" => Some(IntakeError::DcqlQueryInvalid),
            "client_metadata" => Some(IntakeError::ClientMetadataInvalid),
            "transaction_data" => Some(IntakeError::TransactionDataInvalid),
            _ => None,
        };
        let value = match invalid {
            Some(error) => serde_json::from_str(value).map_err(|_| error)?,
            None => Value::String(value.clone()),
        };
        object.insert(name.clone(), value);
    }
    let value = client_id.value().to_owned();
    let trusted = trust::verdict(
        answers,
        TrustSubject::Client(client_id.clone()),
        KeyMaterial::None,
    )?;
    let verifier = by_request(client_id, trusted, UriRule::Equals(value));
    Ok(request::verified(&object, Arrival::Redirect(verifier))?)
}
