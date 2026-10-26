//! The host's responses to the fetches a plan asks for (H1).

use siros_oid4vp::{Fetch, FetchResponse};
use siros_transaction_data::Fetched;

/// The host's response to each fetch a plan asked for, in the order the host answered.
#[derive(Debug, Clone, Default)]
pub struct Fetches {
    answers: Vec<(Fetch, FetchResponse)>,
}

impl Fetches {
    /// No response yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `response`, the host's response to `fetch`. A later response to the same URL
    /// replaces it.
    pub fn answer(&mut self, fetch: Fetch, response: FetchResponse) {
        self.answers.retain(|(asked, _)| asked.url() != fetch.url());
        self.answers.push((fetch, response));
    }

    /// The response to a fetch of the URL `fetch` names.
    pub(crate) fn response(&self, fetch: &Fetch) -> Option<&FetchResponse> {
        self.answers
            .iter()
            .find(|(asked, _)| asked.url() == fetch.url())
            .map(|(_, response)| response)
    }

    /// The responses, as the transaction data's documents read them.
    pub(crate) fn fetched(&self) -> Fetched {
        let mut fetched = Fetched::new();
        for (fetch, response) in &self.answers {
            // Each URL is recorded once.
            drop(fetched.insert(fetch, response.clone()));
        }
        fetched
    }
}
