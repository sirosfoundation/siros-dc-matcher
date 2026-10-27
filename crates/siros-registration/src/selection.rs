//! The credential picker's transaction data selection over a registration (K2).

use siros_oid4vp::UnverifiedRequest;
use siros_presentation::{MatchRequest, TransactionSource};
use siros_transaction_data::{Deferral, Entry, Selection, Selector, TransactionDataError};

use crate::registration::{RegisteredCredential, Registration};

/// The picker's selection: each credential's first match over the definitions the wallet
/// registered, at the registration's time, over the channel the request came by. An entry with
/// ad-hoc metadata is deferred to the wallet, which verifies it after selection.
pub struct Unverified {
    selector: Selector,
}

impl Unverified {
    /// The selection over `registration` of `request`.
    pub fn new(registration: &Registration, request: &UnverifiedRequest) -> Self {
        Self {
            selector: Selector {
                channel: request.channel(),
                signature: request.signature(),
                now: registration.registered_at(),
            },
        }
    }
}

impl<'c> TransactionSource<&'c RegisteredCredential> for Unverified {
    type Deferral = Deferral;

    fn first_match(
        &self,
        entries: &[&Entry],
        credential: &&'c RegisteredCredential,
    ) -> Result<Selection<Deferral>, TransactionDataError> {
        self.selector.first_match_unverified(entries, *credential)
    }

    /// Whether a source defines the entry's type: the entry's ad-hoc metadata does when it has
    /// some, verified or not; else the registered sources.
    fn knows(&self, entry: &Entry, credential: &&'c RegisteredCredential) -> bool {
        entry.metadata().is_some()
            || credential
                .transactions
                .serve(entry.type_id())
                .map_or_else(|reason| reason.type_defined(), |_| true)
    }
}
