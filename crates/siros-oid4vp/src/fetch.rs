//! The `Fetch` effect: an HTTPS request the host performs, and its response (host effect H1).

use std::time::Duration;

use serde::{Deserialize, Serialize};
use siros_codec::locale::Locale;
pub use siros_codec::url::HttpsUrl;

/// A media type a fetch accepts or a body has, `type/subtype`; or, as the `Accept` value of an
/// image fetch, the list of the image types the wallet shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MediaType(&'static str);

impl MediaType {
    /// `application/json`.
    pub const JSON: Self = Self("application/json");
    /// `application/oauth-authz-req+jwt`, a Request Object (RFC 9101, Section 10.2).
    pub const REQUEST_OBJECT: Self = Self("application/oauth-authz-req+jwt");
    /// `application/x-www-form-urlencoded`.
    pub const FORM: Self = Self("application/x-www-form-urlencoded");
    /// `application/cwt`, the body of `direct_post.cwt` (`zkp_req.md`, Section 6.2).
    pub const CWT: Self = Self("application/cwt");
    /// `application/jwt`: a signed credential metadata JWT (PaSO Proof Metadata, Section 2).
    pub const JWT: Self = Self("application/jwt");
    /// The image types the wallet shows: PNG, JPEG and SVG (PaSO View, Section 3, `image`).
    pub const IMAGES: Self = Self("image/png, image/jpeg, image/svg+xml");

    /// `type/subtype`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

/// The most bytes of a response body the host may read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BodyLimit(usize);

impl BodyLimit {
    /// At most `bytes` bytes.
    #[must_use]
    pub const fn bytes(bytes: usize) -> Self {
        Self(bytes)
    }

    /// The number of bytes.
    #[must_use]
    pub fn get(self) -> usize {
        self.0
    }

    /// Whether `body` is within the limit.
    #[must_use]
    pub fn admits(self, body: &[u8]) -> bool {
        body.len() <= self.0
    }
}

/// The HTTP method of a [`Fetch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// `GET`, without a body.
    Get,
    /// `POST`, with a body.
    Post {
        /// The `Content-Type` of the body.
        content_type: MediaType,
        /// The body.
        body: Vec<u8>,
    },
}

/// An HTTPS request the host performs under H1: HTTPS only, public addresses only, no
/// redirects, at most [`Fetch::limit`] of response body, within [`Fetch::timeout`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetch {
    url: HttpsUrl,
    method: Method,
    accept: MediaType,
    language: Option<Locale>,
    limit: BodyLimit,
}

impl Fetch {
    pub(crate) fn new(url: HttpsUrl, method: Method, accept: MediaType, limit: BodyLimit) -> Self {
        Self {
            url,
            method,
            accept,
            language: None,
            limit,
        }
    }

    /// A `GET` of `url` that accepts `accept` and reads at most `limit`.
    #[must_use]
    pub fn get(url: HttpsUrl, accept: MediaType, limit: BodyLimit) -> Self {
        Self::new(url, Method::Get, accept, limit)
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

    /// The fetch with the `Accept-Language` header `language`.
    #[must_use]
    pub fn in_language(self, language: Locale) -> Self {
        Self {
            language: Some(language),
            ..self
        }
    }

    /// The `Accept` header value.
    #[must_use]
    pub fn accept(&self) -> MediaType {
        self.accept
    }

    /// The `Accept-Language` header value, when the fetch carries one.
    #[must_use]
    pub fn accept_language(&self) -> Option<&Locale> {
        self.language.as_ref()
    }

    /// The largest response body the host may read.
    #[must_use]
    pub fn limit(&self) -> BodyLimit {
        self.limit
    }

    /// The time the host may wait for the whole response.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        TIMEOUT
    }
}

/// The time every [`Fetch`] gets.
const TIMEOUT: Duration = Duration::from_secs(10);

/// An HTTP status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HttpStatus(u16);

impl HttpStatus {
    /// `200 OK`.
    pub const OK: Self = Self(200);

    /// The status `code`.
    #[must_use]
    pub fn new(code: u16) -> Self {
        Self(code)
    }

    /// The code.
    #[must_use]
    pub fn code(self) -> u16 {
        self.0
    }
}

/// The response to a [`Fetch`], as the host received it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchResponse {
    status: HttpStatus,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl FetchResponse {
    /// A response: its HTTP status, its `Content-Type` header when present, and its body.
    #[must_use]
    pub fn new(status: HttpStatus, content_type: Option<String>, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }

    /// The HTTP status.
    #[must_use]
    pub fn status(&self) -> HttpStatus {
        self.status
    }

    /// Whether the media type of `Content-Type`, parameters aside, is `media_type` (any
    /// case).
    pub(crate) fn has_media_type(&self, media_type: MediaType) -> bool {
        self.content_type.as_deref().is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case(media_type.as_str()))
        })
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}
