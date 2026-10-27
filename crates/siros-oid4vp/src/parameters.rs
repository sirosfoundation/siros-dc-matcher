//! The rules of a request's parameters that need no key and no origin (OpenID4VP 1.0, Sections
//! 5.1, 5.2, 5.6, 8.2; A.2; RFC 9101, Section 4). Intake applies them to the request it
//! verifies, and [`UnverifiedRequest`](crate::UnverifiedRequest) to the request the credential
//! picker reads, so both refuse a request alike.

use serde_json::{Map, Value};
use siros_dcql::DcqlQuery;

use crate::request::AttestationFormat;

/// A rule of a request's parameters that a request breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum ParameterFault {
    /// The Request Object holds `request` or `request_uri` (RFC 9101, Section 4).
    NestedRequest,
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
    /// A signed DC API request has no non-empty `expected_origins` of strings (A.2).
    ExpectedOriginsMissing,
    /// `client_metadata` is not a JSON object.
    ClientMetadataInvalid,
    /// `verifier_info` breaks a rule of Section 5.1.
    VerifierInfo(#[source] VerifierInfoRule),
}

impl ParameterFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NestedRequest => "nested_request",
            Self::ResponseTypeUnsupported => "response_type_unsupported",
            Self::NonceInvalid => "nonce_invalid",
            Self::StateInvalid => "state_invalid",
            Self::ResponseModeUnsupported => "response_mode_unsupported",
            Self::ExpectedOriginsMissing => "expected_origins_missing",
            Self::ClientMetadataInvalid => "client_metadata_invalid",
            Self::VerifierInfo(rule) => rule.code(),
        }
    }
}

/// A rule of `verifier_info` (Section 5.1) that a request breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
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

/// `nonce` (Section 5.2): ASCII URL-safe characters, at least one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nonce(String);

/// `state` (Section 5.2): ASCII URL-safe characters, at least one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct State(String);

/// `text` when it holds ASCII URL-safe characters only, at least one (Section 5.2).
fn url_safe(text: &str) -> Option<String> {
    let safe = text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    (!text.is_empty() && safe).then(|| text.to_owned())
}

impl Nonce {
    /// The nonce `text`; `None` for text with another character, or none.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        url_safe(text).map(Self)
    }

    /// The nonce.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl State {
    /// The state `text`; `None` for text with another character, or none.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        url_safe(text).map(Self)
    }

    /// The state.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The parameters of every request: its `nonce` and `state`.
pub(crate) struct Plain {
    pub(crate) nonce: Nonce,
    pub(crate) state: Option<State>,
}

/// The `nonce` and `state` of the request parameters `params`, which hold no nested request
/// and `response_type` `vp_token`.
///
/// # Errors
///
/// [`ParameterFault`]: the first rule `params` breaks.
pub(crate) fn plain(params: &Map<String, Value>) -> Result<Plain, ParameterFault> {
    let text = |name: &str| params.get(name).and_then(Value::as_str);
    if params.contains_key("request") || params.contains_key("request_uri") {
        return Err(ParameterFault::NestedRequest);
    }
    if text("response_type") != Some("vp_token") {
        return Err(ParameterFault::ResponseTypeUnsupported);
    }
    let nonce = text("nonce")
        .and_then(Nonce::parse)
        .ok_or(ParameterFault::NonceInvalid)?;
    let state = params
        .get("state")
        .map(|state| {
            state
                .as_str()
                .and_then(State::parse)
                .ok_or(ParameterFault::StateInvalid)
        })
        .transpose()?;
    Ok(Plain { nonce, state })
}

/// The body a redirect Response Mode names.
#[cfg(feature = "crypto")]
pub(crate) enum Encoding {
    Form,
    Jwe,
    Cose,
}

#[cfg(feature = "crypto")]
impl Encoding {
    /// The body of the Response Mode `mode`: `direct_post`, `direct_post.jwt` or
    /// `direct_post.cwt` (Section 8.2; `zkp_req.md`, Section 6.2).
    pub(crate) fn of(mode: Option<&str>) -> Result<Self, ParameterFault> {
        match mode {
            Some("direct_post") => Ok(Self::Form),
            Some("direct_post.jwt") => Ok(Self::Jwe),
            Some("direct_post.cwt") => Ok(Self::Cose),
            _ => Err(ParameterFault::ResponseModeUnsupported),
        }
    }
}

/// The `data` a DC API Response Mode names (A.2).
pub(crate) enum DcApiEncoding {
    /// `dc_api`: the response parameters.
    Json,
    /// `dc_api.jwt`: their JWE.
    Jwe,
}

impl DcApiEncoding {
    /// The `data` of the Response Mode `mode`: `dc_api` or `dc_api.jwt`.
    pub(crate) fn of(mode: Option<&str>) -> Result<Self, ParameterFault> {
        match mode {
            Some("dc_api") => Ok(Self::Json),
            Some("dc_api.jwt") => Ok(Self::Jwe),
            _ => Err(ParameterFault::ResponseModeUnsupported),
        }
    }
}

/// `expected_origins` of a signed DC API request: a non-empty array of strings (A.2).
///
/// # Errors
///
/// [`ParameterFault::ExpectedOriginsMissing`] for any other value.
pub(crate) fn expected_origins(params: &Map<String, Value>) -> Result<Vec<String>, ParameterFault> {
    params
        .get("expected_origins")
        .and_then(strings)
        .filter(|origins| !origins.is_empty())
        .ok_or(ParameterFault::ExpectedOriginsMissing)
}

/// `client_metadata` of a request whose Verifier metadata comes from the request: a JSON
/// object, when present.
///
/// # Errors
///
/// [`ParameterFault::ClientMetadataInvalid`] for another JSON value.
pub(crate) fn request_metadata(
    params: &Map<String, Value>,
) -> Result<Option<Value>, ParameterFault> {
    match params.get("client_metadata") {
        None => Ok(None),
        Some(metadata @ Value::Object(_)) => Ok(Some(metadata.clone())),
        Some(_) => Err(ParameterFault::ClientMetadataInvalid),
    }
}

/// The `format` of each attestation of `verifier_info` (Section 5.1): a non-empty array of
/// objects, each with a string `format`, a `data` object or string, and `credential_ids`, when
/// present, a non-empty array of the ids of Credential Queries of `query`.
///
/// # Errors
///
/// [`ParameterFault::VerifierInfo`] with the rule `value` breaks.
pub(crate) fn verifier_info(
    value: Option<&Value>,
    query: &DcqlQuery,
) -> Result<Vec<AttestationFormat>, ParameterFault> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let attestations = value.as_array().ok_or(VerifierInfoRule::NotArray);
    let attestations = attestations.map_err(ParameterFault::VerifierInfo)?;
    if attestations.is_empty() {
        return Err(ParameterFault::VerifierInfo(VerifierInfoRule::Empty));
    }
    attestations
        .iter()
        .map(|attestation| {
            attestation_format(attestation, query).map_err(ParameterFault::VerifierInfo)
        })
        .collect()
}

/// The `format` of the `verifier_info` attestation `attestation`.
fn attestation_format(
    attestation: &Value,
    query: &DcqlQuery,
) -> Result<AttestationFormat, VerifierInfoRule> {
    let attestation = attestation.as_object().ok_or(VerifierInfoRule::NotObject)?;
    let format = attestation
        .get("format")
        .and_then(Value::as_str)
        .ok_or(VerifierInfoRule::Format)?;
    if !attestation
        .get("data")
        .is_some_and(|data| data.is_object() || data.is_string())
    {
        return Err(VerifierInfoRule::Data);
    }
    if let Some(ids) = attestation.get("credential_ids") {
        let ids = strings(ids)
            .filter(|ids| !ids.is_empty())
            .ok_or(VerifierInfoRule::CredentialIds)?;
        if !ids.iter().all(|id| query.credential(id).is_some()) {
            return Err(VerifierInfoRule::CredentialIdUnknown);
        }
    }
    Ok(AttestationFormat::new(format))
}

/// A JSON array of strings.
pub(crate) fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}
