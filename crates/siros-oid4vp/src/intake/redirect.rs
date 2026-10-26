//! Intake of an authorization request URI: parameters by value, a Request Object by value
//! (`request`), or by reference (`request_uri`, Section 5.10; RFC 9101, Section 5).

use rustc_hash::FxHashMap;
use serde_json::{Map, Value};
use siros_codec::date::DateTime;

use super::request::{self, Arrival};
use super::signature::{self, by_request, UriRule};
use super::trust::{self, KeyMaterial, TrustSubject};
use super::{Answers, FormFault, Halt, IntakeError, JwsFault};
use crate::client_id::{ClientId, ClientIdPrefix};
use crate::fetch::{BodyLimit, Fetch, HttpStatus, HttpsUrl, MediaType, Method};
use crate::form;
use crate::jose;
use crate::values::WalletNonce;
use crate::verified::VerifiedRequest;

/// The largest Request Object fetched.
const MAX_REQUEST_OBJECT: BodyLimit = BodyLimit::bytes(256 * 1024);

/// What the wallet posts for `request_uri_method=post` (Section 5.10).
pub(super) struct Wallet<'a> {
    pub(super) vp_formats_supported: &'a Map<String, Value>,
    pub(super) nonce: &'a WalletNonce,
}

/// How the wallet fetches a Request Object by reference (Section 5.10).
#[derive(Clone, Copy)]
enum RequestUriMethod {
    /// `get`, the default: a plain `GET`.
    Get,
    /// `post`: a `POST` of the wallet's metadata and nonce, which the Request Object echoes.
    Post,
}

impl RequestUriMethod {
    /// The method `request_uri_method` names; `get` when absent.
    fn parse(method: Option<&str>) -> Result<Self, IntakeError> {
        match method {
            None | Some("get") => Ok(Self::Get),
            Some("post") => Ok(Self::Post),
            Some(_) => Err(IntakeError::RequestUriMethodInvalid),
        }
    }
}

/// Intake of the authorization request URI `uri`.
pub(super) fn intake(
    uri: &str,
    wallet: &Wallet<'_>,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let refused = IntakeError::NotAnAuthorizationRequest;
    let query = uri
        .split_once('?')
        .and_then(|(_, rest)| rest.split('#').next())
        .ok_or(refused(FormFault::NoQuery))?;
    let params = form::parse(query).map_err(refused)?;
    let outer = params
        .get("client_id")
        .ok_or(IntakeError::ClientIdMissing)?;
    let method = params.get("request_uri_method").map(String::as_str);
    match (params.get("request"), params.get("request_uri")) {
        (Some(_), Some(_)) => Err(IntakeError::RequestAndRequestUri.into()),
        (_, None) if method.is_some() => Err(IntakeError::RequestUriMethodWithoutRequestUri.into()),
        (Some(jws), None) => signed(jws, outer, None, now, answers),
        (None, Some(request_uri)) => {
            let method = RequestUriMethod::parse(method)?;
            // A `redirect_uri` client cannot sign, so its Request Object is not fetched.
            if ClientId::parse(outer)?.prefix() == ClientIdPrefix::RedirectUri {
                return Err(IntakeError::SignedRedirectUri.into());
            }
            let url = HttpsUrl::parse(request_uri).ok_or(IntakeError::RequestUriNotHttps)?;
            let fetch = Fetch::new(
                url,
                fetch_method(method, wallet),
                MediaType::REQUEST_OBJECT,
                MAX_REQUEST_OBJECT,
            );
            let response = answers.fetch(fetch)?;
            if response.status() != HttpStatus::OK {
                return Err(IntakeError::FetchStatus.into());
            }
            if !response.has_media_type(MediaType::REQUEST_OBJECT) {
                return Err(IntakeError::FetchContentType.into());
            }
            if !MAX_REQUEST_OBJECT.admits(response.body()) {
                return Err(IntakeError::FetchTooLarge.into());
            }
            let jws = std::str::from_utf8(response.body())
                .map_err(|_| IntakeError::JwsMalformed(JwsFault::NotUtf8))?;
            let echoed = match method {
                RequestUriMethod::Get => None,
                RequestUriMethod::Post => Some(wallet.nonce),
            };
            signed(jws.trim(), outer, echoed, now, answers)
        }
        (None, None) => unsigned(&params, outer, answers),
    }
}

/// The method of the Request Object fetch.
fn fetch_method(method: RequestUriMethod, wallet: &Wallet<'_>) -> Method {
    match method {
        RequestUriMethod::Get => Method::Get,
        RequestUriMethod::Post => {
            let metadata = wallet_metadata(wallet.vp_formats_supported);
            Method::Post {
                content_type: MediaType::FORM,
                body: form::encode(&[
                    ("wallet_metadata", &metadata),
                    ("wallet_nonce", wallet.nonce.as_str()),
                ])
                .into_bytes(),
            }
        }
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
    wallet_nonce: Option<&WalletNonce>,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<VerifiedRequest, Halt> {
    let (signed, payload) = jose::compact(jws).map_err(IntakeError::from)?;
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
        if object.get("wallet_nonce").and_then(Value::as_str) != Some(nonce.as_str()) {
            return Err(IntakeError::WalletNonceMismatch.into());
        }
    }
    let verifier = signature::authenticate(&signed, ClientId::parse(inner)?, now, answers)?;
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
    let object = params
        .iter()
        .map(|(name, value)| Ok((name.clone(), parameter(name, value)?)))
        .collect::<Result<Map<String, Value>, IntakeError>>()?;
    let trusted = trust::verdict(
        answers,
        TrustSubject::Client(client_id.clone()),
        KeyMaterial::None,
    )?;
    let verifier = by_request(client_id, trusted, UriRule::IsClientIdValue);
    Ok(request::verified(&object, Arrival::Redirect(verifier))?)
}

/// The request parameter `name` of the form value `value`. Section 5.1: parameters holding
/// objects travel as JSON-serialized strings.
fn parameter(name: &str, value: &str) -> Result<Value, IntakeError> {
    let invalid = match name {
        "dcql_query" => IntakeError::DcqlQueryInvalid,
        "client_metadata" => IntakeError::ClientMetadataInvalid,
        "transaction_data" => IntakeError::TransactionDataInvalid,
        _ => return Ok(Value::String(value.to_owned())),
    };
    serde_json::from_str(value).map_err(|_| invalid)
}
