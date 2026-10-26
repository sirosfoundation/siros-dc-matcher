//! The response to a verified request (P4, P5): the `vp_token` (Section 8.1), its submission
//! in the form of the Response Mode, error submissions (Section 8.5), and the Verifier's reply
//! to a direct post (Section 8.2).

mod jwe;

use std::fmt;

use rand_core::CryptoRngCore;
use serde_json::{Map, Value};

pub use jwe::concat_kdf;

use crate::error_code::ErrorCode;
use crate::fetch::{Fetch, FetchResponse, HttpsUrl, Method};
use crate::form;
use crate::verified::{Channel, VerifiedRequest};

/// The media type the Response URI answers with (Section 8.2).
const REPLY_MEDIA_TYPE: &str = "application/json";

/// The largest reply to a direct post read, in bytes.
const MAX_REPLY: usize = 64 * 1024;

/// What the wallet sends the Verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// `direct_post` and `direct_post.jwt`: a form POST to the Response URI. Its reply goes to
    /// [`read_reply`].
    Post(Fetch),
    /// `dc_api` and `dc_api.jwt`: the `data` object the platform returns to the caller (A.4).
    DcApi(Value),
}

impl Submission {
    /// `{"error": code}`, as the DC API returns a refusal (A.4).
    pub(crate) fn dc_api_error(code: ErrorCode) -> Self {
        let mut data = Map::new();
        data.insert("error".into(), code.as_str().into());
        Self::DcApi(Value::Object(data))
    }
}

/// Why no response could be built or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseError {
    /// A `vp_token` key is not the `id` of a Credential Query of the request.
    UnknownQueryId,
    /// A `vp_token` key repeats.
    DuplicateQueryId,
    /// A `vp_token` entry has no presentation.
    NoPresentation,
    /// A `vp_token` entry has several presentations, and its query does not set `multiple`.
    MultipleNotAllowed,
    /// A presentation is neither a string nor an object (Section 8.1).
    PresentationNotStringOrObject,
    /// The JWE could not be produced.
    EncryptionFailed,
    /// The Response URI answered with a status other than 200 (Section 8.2).
    ReplyStatus,
    /// The Response URI answered with a media type other than `application/json`.
    ReplyContentType,
    /// The reply is longer than the fetch allowed, or not a JSON object.
    ReplyNotObject,
    /// The reply's `redirect_uri` is not an absolute URI (RFC 3986, Section 4.3).
    RedirectUriInvalid,
}

impl ResponseError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownQueryId => "unknown_query_id",
            Self::DuplicateQueryId => "duplicate_query_id",
            Self::NoPresentation => "no_presentation",
            Self::MultipleNotAllowed => "multiple_not_allowed",
            Self::PresentationNotStringOrObject => "presentation_not_string_or_object",
            Self::EncryptionFailed => "encryption_failed",
            Self::ReplyStatus => "reply_status",
            Self::ReplyContentType => "reply_content_type",
            Self::ReplyNotObject => "reply_not_object",
            Self::RedirectUriInvalid => "redirect_uri_invalid",
        }
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ResponseError {}

/// A `vp_token` for one verified request (Section 8.1).
///
/// Its existence guarantees that each key is the `id` of a Credential Query of the request,
/// once, with at least one presentation, and exactly one unless the query sets `multiple`;
/// each presentation is a string or an object.
#[derive(Debug, Clone)]
pub struct VpToken<'r> {
    request: &'r VerifiedRequest,
    token: Map<String, Value>,
}

impl VerifiedRequest {
    /// The `vp_token` of `entries`: the presentations answering each Credential Query, by its
    /// `id`.
    ///
    /// # Errors
    ///
    /// [`ResponseError`]: the first rule of Section 8.1 an entry breaks.
    pub fn vp_token(
        &self,
        entries: Vec<(String, Vec<Value>)>,
    ) -> Result<VpToken<'_>, ResponseError> {
        let mut token = Map::new();
        for (id, presentations) in entries {
            let query = self
                .dcql_query
                .credential(&id)
                .ok_or(ResponseError::UnknownQueryId)?;
            match presentations.len() {
                0 => return Err(ResponseError::NoPresentation),
                1 => {}
                _ if !query.multiple => return Err(ResponseError::MultipleNotAllowed),
                _ => {}
            }
            if !presentations
                .iter()
                .all(|p| matches!(p, Value::String(_) | Value::Object(_)))
            {
                return Err(ResponseError::PresentationNotStringOrObject);
            }
            if token.insert(id, Value::Array(presentations)).is_some() {
                return Err(ResponseError::DuplicateQueryId);
            }
        }
        Ok(VpToken {
            request: self,
            token,
        })
    }

    /// The submission refusing this request with `code` (P5: the response target is
    /// verified). Over redirects it carries `state`; `direct_post.jwt` encrypts it with a key
    /// and IV from `rng`.
    ///
    /// # Errors
    ///
    /// [`ResponseError::EncryptionFailed`].
    pub fn error_submission(
        &self,
        code: ErrorCode,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Submission, ResponseError> {
        let mut parameters = Map::new();
        parameters.insert("error".into(), code.as_str().into());
        match &self.channel {
            Channel::Redirect { response_uri, .. } => self.post(response_uri, parameters, rng),
            Channel::DcApi { .. } => Ok(Submission::dc_api_error(code)),
        }
    }

    /// The submission of the response `parameters` in the form of the Response Mode (P4).
    fn submit(
        &self,
        parameters: Map<String, Value>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Submission, ResponseError> {
        match &self.channel {
            Channel::Redirect { response_uri, .. } => self.post(response_uri, parameters, rng),
            Channel::DcApi { .. } => {
                let data = match &self.encryption {
                    None => parameters,
                    Some(encryption) => {
                        let payload = Value::Object(parameters).to_string();
                        let mut data = Map::new();
                        let jwe = jwe::encrypt(encryption, payload.as_bytes(), rng)?;
                        data.insert("response".into(), jwe.into());
                        data
                    }
                };
                Ok(Submission::DcApi(Value::Object(data)))
            }
        }
    }

    /// A form POST to `response_uri` of `parameters` and `state`: each as a form parameter
    /// for `direct_post`, together in the JWE of `response` for `direct_post.jwt`.
    fn post(
        &self,
        response_uri: &HttpsUrl,
        mut parameters: Map<String, Value>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Submission, ResponseError> {
        if let Some(state) = &self.state {
            parameters.insert("state".into(), state.as_str().into());
        }
        let body = match &self.encryption {
            None => {
                let fields: Vec<(String, String)> = parameters
                    .into_iter()
                    .map(|(name, value)| match value {
                        Value::String(text) => (name, text),
                        other => (name, other.to_string()),
                    })
                    .collect();
                let pairs: Vec<(&str, &str)> = fields
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
                    .collect();
                form::encode(&pairs)
            }
            Some(encryption) => {
                let payload = Value::Object(parameters).to_string();
                let jwe = jwe::encrypt(encryption, payload.as_bytes(), rng)?;
                form::encode(&[("response", &jwe)])
            }
        };
        Ok(Submission::Post(Fetch::new(
            response_uri.clone(),
            Method::PostForm { body },
            REPLY_MEDIA_TYPE,
            MAX_REPLY,
        )))
    }
}

impl VpToken<'_> {
    /// The submission of this `vp_token` in the form of the request's Response Mode (P4):
    ///
    /// | Mode | Form |
    /// |---|---|
    /// | `direct_post` | form parameters `vp_token`, `state` |
    /// | `direct_post.jwt` | form parameter `response`: the JWE of `{vp_token, state}` |
    /// | `dc_api` | `{vp_token}` |
    /// | `dc_api.jwt` | `{response}`: the JWE of `{vp_token}` |
    ///
    /// `rng` gives the ephemeral key and IV of an encrypted mode.
    ///
    /// # Errors
    ///
    /// [`ResponseError::EncryptionFailed`].
    pub fn submission(&self, rng: &mut impl CryptoRngCore) -> Result<Submission, ResponseError> {
        let mut parameters = Map::new();
        parameters.insert("vp_token".into(), Value::Object(self.token.clone()));
        self.request.submit(parameters, rng)
    }
}

/// The Verifier's reply to a [`Submission::Post`]: the `redirect_uri` the wallet sends the
/// user agent to, when present (Section 8.2).
///
/// # Errors
///
/// [`ResponseError`]: a status other than 200, a media type other than `application/json`, a
/// body that is not a JSON object, or a `redirect_uri` that is not an absolute URI.
pub fn read_reply(response: &FetchResponse) -> Result<Option<String>, ResponseError> {
    if response.status() != 200 {
        return Err(ResponseError::ReplyStatus);
    }
    if !response.has_media_type(REPLY_MEDIA_TYPE) {
        return Err(ResponseError::ReplyContentType);
    }
    if response.body().len() > MAX_REPLY {
        return Err(ResponseError::ReplyNotObject);
    }
    let Ok(Value::Object(reply)) = serde_json::from_slice(response.body()) else {
        return Err(ResponseError::ReplyNotObject);
    };
    match reply.get("redirect_uri") {
        None => Ok(None),
        Some(Value::String(uri)) if absolute_uri(uri) => Ok(Some(uri.clone())),
        Some(_) => Err(ResponseError::RedirectUriInvalid),
    }
}

/// `scheme ":" …` with `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986,
/// Section 3.1), something after the colon, and no whitespace or control character.
fn absolute_uri(uri: &str) -> bool {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return false;
    };
    let mut chars = scheme.bytes();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        && !rest.is_empty()
        && !uri
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}
