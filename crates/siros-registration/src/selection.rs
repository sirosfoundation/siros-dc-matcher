//! The credential picker's transaction data selection over a registration (K2).

use siros_presentation::TransactionSource;
use siros_transaction_data::{
    Deferral, Entry, Selection, Selector, Step, TransactionDataError, Unfetched,
};

use crate::registration::{RegisteredCredential, Registration};

/// The picker's selection: each credential's first match over the definitions the wallet
/// registered, at the registration's time. An entry with ad-hoc metadata, and an entry with an
/// image at an `https` URL, is deferred to the wallet, which verifies them after selection.
pub struct Unverified {
    selector: Selector<'static, Unfetched>,
}

impl Unverified {
    /// The selection over `registration` of a request that arrived as `signature` says. The
    /// picker fetches no image.
    pub fn new(registration: &Registration, signature: siros_oid4vp::RequestSignature) -> Self {
        Self {
            selector: Selector {
                fetched: &Unfetched,
                signature,
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
    ) -> Result<Step<Selection<Deferral>>, TransactionDataError> {
        self.selector
            .first_match_unverified(entries, *credential)
            .map(Step::Done)
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
