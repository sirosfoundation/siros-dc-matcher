//! The credential picker's transaction data selection over a registration (K2).

use siros_oid4vp::UnverifiedRequest;
use siros_presentation::{MatchRequest, TransactionSource};
use siros_transaction_data::{
    Deferral, Entry, Projected, Selection, Selector, TransactionDataError,
};

use crate::registration::{Facts, RegisteredCredential};

/// The picker's selection: each credential's first match over the definitions the wallet
/// registered, at the registration's time, over the channel the request came by. An entry with
/// ad-hoc metadata is deferred to the wallet, which verifies it after selection.
pub struct Unverified {
    selector: Selector,
}

impl Unverified {
    /// The selection of `request` over a registration of `facts`.
    pub fn new<I>(facts: &Facts<I>, request: &UnverifiedRequest) -> Self {
        Self {
            selector: Selector {
                channel: request.channel(),
                signature: request.signature(),
                now: facts.registered_at(),
            },
        }
    }
}

/// A credential with the definitions read that its sources serve for the types the request's
/// entries name for it ([`RegisteredCredential::select`]).
impl<'c, I> TransactionSource<&'c RegisteredCredential<Projected, I>> for Unverified {
    type Deferral = Deferral;

    fn first_match(
        &self,
        entries: &[&Entry],
        credential: &&'c RegisteredCredential<Projected, I>,
    ) -> Result<Selection<Deferral>, TransactionDataError> {
        self.selector.first_match_unverified(entries, *credential)
    }

    /// Whether a source defines the entry's type: the entry's ad-hoc metadata does when it has
    /// some, verified or not; else the registered sources.
    fn knows(&self, entry: &Entry, credential: &&'c RegisteredCredential<Projected, I>) -> bool {
        entry.metadata().is_some()
            || credential
                .transactions
                .serve(entry.type_id())
                .map_or_else(|reason| reason.type_defined(), |_| true)
    }
}
