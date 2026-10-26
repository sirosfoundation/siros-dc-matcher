//! The host's responses to the fetches a plan asks for (H1).

use siros_oid4vp::{Fetch, FetchResponse};
use siros_transaction_data::Fetched;

use crate::error::PresentationError;

/// The host's response to each fetch a plan asked for: one store, which the plan and its view
/// read.
#[derive(Default)]
pub struct Fetches(Fetched);

impl Fetches {
    /// No response yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `response`, the host's response to `fetch`.
    ///
    /// # Errors
    ///
    /// [`PresentationError::FetchRepeated`] when the host answered a fetch of the URL already.
    pub fn answer(
        &mut self,
        fetch: &Fetch,
        response: FetchResponse,
    ) -> Result<(), PresentationError> {
        self.0
            .insert_first(fetch, response)
            .map(drop)
            .map_err(|_| PresentationError::FetchRepeated(fetch.url().clone()))
    }

    /// The response to a fetch of the URL `fetch` names.
    pub(crate) fn response(&self, fetch: &Fetch) -> Option<&FetchResponse> {
        self.0.response(fetch)
    }

    /// The responses, as the transaction data's documents read them.
    pub(crate) fn fetched(&self) -> &Fetched {
        &self.0
    }
}
