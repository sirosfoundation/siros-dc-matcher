//! The response to a verified request (P4, P5): the `vp_token` (Section 8.1), its submission
//! in the form of the Response Mode, error submissions (Section 8.5), and the Verifier's reply
//! to a direct post (Section 8.2).

mod aead;
mod cose;
mod jwe;
mod vp_token;

use std::fmt;

use rand_core::CryptoRngCore;
use serde_json::{Map, Value};

pub use cose::cose_kdf;
pub use jwe::concat_kdf;
pub use vp_token::{Presentation, VpToken};

use crate::error_code::ErrorCode;
use crate::fetch::{Fetch, FetchResponse, Method};
use crate::form;
use crate::verified::{Channel, PostEncoding, VerifiedRequest};
use vp_token::Answer;

/// The media type the Response URI answers with (Section 8.2).
const REPLY_MEDIA_TYPE: &str = "application/json";

/// The media type of a form body.
const FORM: &str = "application/x-www-form-urlencoded";

/// The media type of a `direct_post.cwt` body (`zkp_req.md`, Section 6.2).
const CWT: &str = "application/cwt";

/// The largest reply to a direct post read, in bytes.
const MAX_REPLY: usize = 64 * 1024;

/// What the wallet sends the Verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// `direct_post`, `direct_post.jwt` and `direct_post.cwt`: a POST to the Response URI. Its
    /// reply goes to [`read_reply`].
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
    /// A CBOR presentation is not one CBOR map.
    PresentationNotCborMap,
    /// The JWE or the `COSE_Encrypt` could not be produced.
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
            Self::PresentationNotCborMap => "presentation_not_cbor_map",
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

impl VerifiedRequest {
    /// The submission refusing this request with `code` (P5: the response target is
    /// verified). Over redirects it carries `state`, encrypted as the Response Mode encrypts,
    /// with a key and IV from `rng`; over the DC API it is `{"error": code}` (A.4).
    ///
    /// # Errors
    ///
    /// [`ResponseError::EncryptionFailed`].
    pub fn error_submission(
        &self,
        code: ErrorCode,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Submission, ResponseError> {
        match &self.channel {
            Channel::Redirect { .. } => self.submit(&Answer::Error(code), rng),
            Channel::DcApi { .. } => Ok(Submission::dc_api_error(code)),
        }
    }

    /// The submission of `answer` in the form of the Response Mode (P4).
    fn submit(
        &self,
        answer: &Answer<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Submission, ResponseError> {
        match &self.channel {
            Channel::Redirect {
                response_uri,
                encoding,
                ..
            } => {
                let state = self.state.as_deref();
                let (content_type, body) = match encoding {
                    PostEncoding::Form => {
                        let fields: Vec<(String, String)> = answer
                            .json(state)
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
                        (FORM, form::encode(&pairs).into_bytes())
                    }
                    PostEncoding::Jwe(encryption) => {
                        let payload = Value::Object(answer.json(state)).to_string();
                        let jwe = jwe::encrypt(encryption, payload.as_bytes(), rng)?;
                        (FORM, form::encode(&[("response", &jwe)]).into_bytes())
                    }
                    PostEncoding::Cose(encryption) => {
                        let payload = answer.cbor(state).encode();
                        (CWT, cose::encrypt(encryption, &payload, rng)?)
                    }
                };
                Ok(Submission::Post(Fetch::new(
                    response_uri.clone(),
                    Method::Post { content_type, body },
                    REPLY_MEDIA_TYPE,
                    MAX_REPLY,
                )))
            }
            Channel::DcApi { encryption, .. } => {
                let parameters = answer.json(None);
                let data = match encryption {
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
}

impl VpToken<'_> {
    /// The submission of this `vp_token` in the form of the request's Response Mode (P4):
    ///
    /// | Mode | Form |
    /// |---|---|
    /// | `direct_post` | form parameters `vp_token`, `state` |
    /// | `direct_post.jwt` | form parameter `response`: the JWE of `{vp_token, state}` |
    /// | `direct_post.cwt` | an `application/cwt` body: the `COSE_Encrypt` of the CBOR `{vp_token, state}` |
    /// | `dc_api` | `{vp_token}` |
    /// | `dc_api.jwt` | `{response}`: the JWE of `{vp_token}` |
    ///
    /// `rng` gives the ephemeral key and IV of an encrypted mode.
    ///
    /// # Errors
    ///
    /// [`ResponseError::EncryptionFailed`].
    pub fn submission(&self, rng: &mut impl CryptoRngCore) -> Result<Submission, ResponseError> {
        self.request.submit(&Answer::VpToken(self), rng)
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
