//! The documents transaction data asks the host for (H1): each a [`Fetch`], its response kept
//! by URL, and a step that waits for a fetch.

use std::collections::hash_map::Entry;

use rustc_hash::FxHashMap;
use siros_oid4vp::{BodyLimit, Fetch, FetchResponse, HttpStatus, HttpsUrl, MediaType};

/// The responses the host gave to the fetches of transaction data, by URL.
#[derive(Debug, Clone, Default)]
pub struct Fetched(FxHashMap<HttpsUrl, FetchResponse>);

/// What a step of transaction data gives: a fetch for the host, or the value.
#[derive(Debug)]
pub enum Step<T> {
    /// The document to fetch. Its response goes to [`Fetched::insert_first`], and the step is
    /// taken again.
    Fetch(Fetch),
    /// The value.
    Done(T),
}

impl Fetched {
    /// No response yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `response`, the host's first response to `fetch`, and gives it as recorded.
    ///
    /// # Errors
    ///
    /// `response`, back, when a response for the URL is recorded already.
    pub fn insert_first(
        &mut self,
        fetch: &Fetch,
        response: FetchResponse,
    ) -> Result<&FetchResponse, FetchResponse> {
        match self.0.entry(fetch.url().clone()) {
            Entry::Occupied(_) => Err(response),
            Entry::Vacant(vacant) => Ok(vacant.insert(response)),
        }
    }

    /// The response recorded for the URL of `fetch`.
    #[must_use]
    pub fn response(&self, fetch: &Fetch) -> Option<&FetchResponse> {
        self.0.get(fetch.url())
    }

    /// The body of the response to a `GET` of `url` accepting `accept`, at most `limit`
    /// bytes; the fetch while the host has not answered it.
    ///
    /// # Errors
    ///
    /// [`FetchFault`]: a status other than 200, or a body over `limit`.
    pub(crate) fn body(
        &self,
        url: &HttpsUrl,
        accept: MediaType,
        limit: BodyLimit,
    ) -> Result<Step<&[u8]>, FetchFault> {
        let fetch = Fetch::get(url.clone(), accept, limit);
        let Some(response) = self.response(&fetch) else {
            return Ok(Step::Fetch(fetch));
        };
        if response.status() != HttpStatus::OK {
            return Err(FetchFault::Status(response.status()));
        }
        let body = response.body();
        if !limit.admits(body) {
            return Err(FetchFault::TooLarge(body.len()));
        }
        Ok(Step::Done(body))
    }
}

/// Why the response to a fetch holds no document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchFault {
    /// The response has this status, not 200.
    Status(HttpStatus),
    /// The body has this many bytes, more than the fetch allowed.
    TooLarge(usize),
}

impl FetchFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Status(_) => "fetch_status",
            Self::TooLarge(_) => "fetch_too_large",
        }
    }
}

siros_codec::display_code!(FetchFault);

impl std::error::Error for FetchFault {}
