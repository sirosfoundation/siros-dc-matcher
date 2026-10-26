//! The `Fetch` effect: an HTTPS request the host performs, and its response (host effect H1).

use serde::{Deserialize, Serialize};

/// An absolute `https` URL with a non-empty authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpsUrl(String);

impl HttpsUrl {
    /// The URL `text`, when its scheme is `https` (any case), an authority follows `//`, and it
    /// holds no ASCII whitespace or control character.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let scheme = text.get(..8)?;
        if !scheme.eq_ignore_ascii_case("https://") {
            return None;
        }
        if text
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            return None;
        }
        let authority = text.get(8..)?.split(['/', '?', '#']).next()?;
        if authority.is_empty() {
            return None;
        }
        Some(Self(text.to_owned()))
    }

    /// The host of the authority: without user information, port or IPv6 brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        let authority = self
            .0
            .get(8..)
            .and_then(|rest| rest.split(['/', '?', '#']).next())
            .unwrap_or_default();
        let host_port = authority.rsplit('@').next().unwrap_or(authority);
        match host_port.strip_prefix('[') {
            Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
            None => host_port.split(':').next().unwrap_or_default(),
        }
    }

    /// The URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The HTTP method of a [`Fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// `GET`, without a body.
    Get,
    /// `POST`, with a body of the content type `application/x-www-form-urlencoded`.
    PostForm {
        /// The form-encoded body.
        body: String,
    },
}

/// An HTTPS request the host performs under H1: HTTPS only, public addresses only, no
/// redirects, at most [`Fetch::max_bytes`] of response body, within [`Fetch::timeout_ms`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    url: HttpsUrl,
    method: Method,
    accept: &'static str,
    max_bytes: usize,
    timeout_ms: u32,
}

impl Fetch {
    pub(crate) fn new(
        url: HttpsUrl,
        method: Method,
        accept: &'static str,
        max_bytes: usize,
    ) -> Self {
        Self {
            url,
            method,
            accept,
            max_bytes,
            timeout_ms: TIMEOUT_MS,
        }
    }

    /// The URL to request.
    #[must_use]
    pub fn url(&self) -> &HttpsUrl {
        &self.url
    }

    /// The method, with the body of a `POST`.
    #[must_use]
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The `Accept` header value.
    #[must_use]
    pub fn accept(&self) -> &'static str {
        self.accept
    }

    /// The largest response body the host may read.
    #[must_use]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// The time the host may wait for the whole response.
    #[must_use]
    pub fn timeout_ms(&self) -> u32 {
        self.timeout_ms
    }
}

/// The time every [`Fetch`] gets.
const TIMEOUT_MS: u32 = 10_000;

/// The response to a [`Fetch`], as the host received it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl FetchResponse {
    /// A response: its HTTP status, its `Content-Type` header when present, and its body.
    #[must_use]
    pub fn new(status: u16, content_type: Option<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }

    pub(crate) fn status(&self) -> u16 {
        self.status
    }

    /// Whether the media type of `Content-Type`, parameters aside, is `media_type` (any
    /// case).
    pub(crate) fn has_media_type(&self, media_type: &str) -> bool {
        self.content_type.as_deref().is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case(media_type))
        })
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}
