//! The images transaction data asks the host for (H1): each a [`Fetch`], its response kept by
//! URL, and a step that waits for a fetch.

use std::collections::hash_map::Entry;
use std::ops::Deref;

use rustc_hash::FxHashMap;
use siros_oid4vp::{Fetch, FetchResponse, HttpStatus, HttpsUrl};

/// The value of the step `$step`, a [`Step`] that is done; the enclosing function returns
/// `Ok(Step::Fetch(fetch))` for a step that asks the host for a fetch.
#[macro_export]
macro_rules! fetched {
    ($step:expr) => {
        match $step {
            $crate::Step::Fetch(fetch) => return Ok($crate::Step::Fetch(fetch)),
            $crate::Step::Done(value) => value,
        }
    };
}

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

impl<T> Step<T> {
    /// The step with `f` applied to its value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Step<U> {
        match self {
            Self::Fetch(fetch) => Step::Fetch(fetch),
            Self::Done(value) => Step::Done(f(value)),
        }
    }
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
}

/// Where the body of a fetch comes from: the host's responses the wallet records, or nothing, for
/// the credential picker.
pub trait Resources {
    /// A body the source gives.
    type Body<'b>: Deref<Target = [u8]>
    where
        Self: 'b;

    /// The body of the response to `fetch`, at most its limit; the fetch while there is none.
    ///
    /// # Errors
    ///
    /// [`FetchFault`]: a status other than 200, or a body over the fetch's limit.
    fn body(&self, fetch: Fetch) -> Result<Step<Self::Body<'_>>, FetchFault>;
}

/// No response: the credential picker fetches nothing, and defers each fetch to the wallet (K2).
#[derive(Debug, Clone, Copy, Default)]
pub struct Unfetched;

/// The body of no response: there is none.
#[derive(Debug, Clone, Copy)]
pub enum NoBody {}

impl Deref for NoBody {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match *self {}
    }
}

impl Resources for Unfetched {
    type Body<'b> = NoBody;

    fn body(&self, fetch: Fetch) -> Result<Step<NoBody>, FetchFault> {
        Ok(Step::Fetch(fetch))
    }
}

impl Resources for Fetched {
    type Body<'b> = &'b [u8];

    fn body(&self, fetch: Fetch) -> Result<Step<&[u8]>, FetchFault> {
        let Some(response) = self.response(&fetch) else {
            return Ok(Step::Fetch(fetch));
        };
        if response.status() != HttpStatus::OK {
            return Err(FetchFault::Status(response.status()));
        }
        let body = response.body();
        if !fetch.limit().admits(body) {
            return Err(FetchFault::TooLarge(body.len()));
        }
        Ok(Step::Done(body))
    }
}

/// Why the response to a fetch holds no document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FetchFault {
    /// The response has this status; only 200 delivers a document.
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
