//! The user's selection, parsed against the plan (A3, A4), and the refusal of a background
//! fulfilment that needs the wallet's display (A9).

use siros_codec::base64url;

use crate::display_rule::WalletDisplay;
use crate::error::PresentationError;
use crate::offers::Member;
use crate::plan::Planned;

/// The user's choice in a consent view, as the UI returns it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selection {
    digest: [u8; 32],
    offer: usize,
    additions: Vec<usize>,
    subsets: Vec<(String, Vec<usize>)>,
}

impl Selection {
    /// The choice of the offer at `offer`, of its additions at `additions`, and for members of
    /// `multiple` queries, by query id, of the credentials at the positions of each subset in
    /// [`MemberView::credentials`](crate::MemberView::credentials), in the view whose
    /// [`ConsentView::digest`](crate::ConsentView::digest) is `digest`. A `multiple` member
    /// without a subset presents every credential the view shows for it.
    ///
    /// # Errors
    ///
    /// [`PresentationError::DigestMalformed`] when `digest` is not 32 bytes of unpadded
    /// base64url.
    pub fn new(
        digest: &str,
        offer: usize,
        additions: Vec<usize>,
        subsets: Vec<(String, Vec<usize>)>,
    ) -> Result<Self, PresentationError> {
        let digest = base64url::decode(digest)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(PresentationError::DigestMalformed)?;
        Ok(Self {
            digest,
            offer,
            additions,
            subsets,
        })
    }
}

/// How the wallet fulfils a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fulfilment {
    /// On its own UI, where the user consented.
    WalletUi,
    /// From its background service, after the user consented on the picker's display.
    Background,
}

/// An offer and additions of a plan that the user chose, with the credentials chosen for each
/// member.
pub struct Chosen<'p, 'a> {
    pub(crate) planned: &'p Planned<'a>,
    /// The offer's members, to which its transaction entries bind.
    pub(crate) members: Vec<Member>,
    /// The members of the chosen additions.
    pub(crate) added: Vec<Member>,
}

impl<'a> Planned<'a> {
    /// The offer `selection` chose in this plan, fulfilled as `fulfilment` says.
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: the digest of another plan; an unknown offer or addition; an
    /// addition chosen twice, a second addition from one optional set, or one answering a query
    /// another chosen addition answers; a subset of no `multiple` member, a second subset for
    /// one, an empty subset, a position out of range or repeated, or a subset that drops a
    /// credential a transaction entry is bound to; or a background fulfilment of an offer that
    /// needs the wallet's display.
    pub fn choose(
        &self,
        selection: &Selection,
        fulfilment: Fulfilment,
    ) -> Result<Chosen<'_, 'a>, PresentationError> {
        if selection.digest != self.digest {
            return Err(PresentationError::DigestMismatch);
        }
        let offer = self
            .offers
            .offers()
            .get(selection.offer)
            .ok_or(PresentationError::OfferUnknown)?;
        let view = self
            .view
            .offers()
            .get(selection.offer)
            .ok_or(PresentationError::OfferUnknown)?;
        let mut added: Vec<Member> = Vec::new();
        let mut sets: Vec<usize> = Vec::with_capacity(selection.additions.len());
        for &index in &selection.additions {
            let addition = offer
                .additions()
                .get(index)
                .ok_or(PresentationError::AdditionUnknown)?;
            let conflicts = sets.contains(&addition.set())
                || addition
                    .members()
                    .iter()
                    .any(|a| added.iter().any(|b| a.query() == b.query()));
            if conflicts {
                return Err(PresentationError::AdditionConflict);
            }
            sets.push(addition.set());
            added.extend(addition.members().iter().cloned());
        }
        let mut members = offer.members().to_vec();
        let mut chosen: Vec<usize> = Vec::with_capacity(selection.subsets.len());
        for (query_id, positions) in &selection.subsets {
            let query = self
                .answered
                .queries()
                .iter()
                .position(|answers| answers.query().multiple && &answers.query().id == query_id)
                .ok_or(PresentationError::SubsetUnknown)?;
            if chosen.contains(&query) {
                return Err(PresentationError::SubsetRepeated);
            }
            chosen.push(query);
            let member = members
                .iter_mut()
                .chain(added.iter_mut())
                .find(|member| member.query() == query)
                .ok_or(PresentationError::SubsetUnknown)?;
            if positions.is_empty() {
                return Err(PresentationError::SubsetEmpty);
            }
            *member = member
                .subset(positions)
                .ok_or(PresentationError::SubsetOutOfRange)?;
        }
        // Every credential an entry is bound to stays, so the binding of the chosen credentials
        // is the plan's (T4).
        for ((at, candidate), _) in self.transactions.bind(&self.answered, offer.members())? {
            let kept = members
                .get(at)
                .is_some_and(|member| member.candidates().contains(&candidate));
            if !kept {
                return Err(PresentationError::SubsetDropsEntry);
            }
        }
        if fulfilment == Fulfilment::Background && view.wallet_display() == WalletDisplay::Needed {
            return Err(PresentationError::WalletDisplayNeeded);
        }
        Ok(Chosen {
            planned: self,
            members,
            added,
        })
    }
}
