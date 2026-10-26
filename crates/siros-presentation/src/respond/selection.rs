//! The user's selection, parsed against the plan (A3, A4), and the refusal of a background
//! fulfilment that needs the wallet's display (A9).

use crate::display_rule::WalletDisplay;
use crate::error::{Inconsistency, PresentationError};
use siros_dcql::QueryId;

use crate::ids::{AdditionIndex, OfferIndex, Position, QueryIndex};
use crate::offers::{Addition, Member, Offer};
use crate::plan::{PlanDigest, Planned};

/// The user's choice in a consent view, as the UI returns it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selection {
    digest: PlanDigest,
    offer: OfferIndex,
    additions: Vec<AdditionIndex>,
    subsets: Vec<Subset>,
}

/// The credentials chosen for the member of a `multiple` Credential Query: their positions in
/// [`MemberView::credentials`](crate::MemberView::credentials).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Subset {
    query: QueryId,
    positions: Vec<Position>,
}

impl Subset {
    /// The credentials at `positions` for the member of the query `query`.
    pub fn new(query: QueryId, positions: Vec<Position>) -> Self {
        Self { query, positions }
    }
}

impl Selection {
    /// The choice of the offer at `offer`, of its additions at `additions`, and of `subsets`
    /// for members of `multiple` queries, in the view whose
    /// [`ConsentView::digest`](crate::ConsentView::digest) is `digest`. A `multiple` member
    /// without a subset presents every credential the view shows for it.
    pub fn new(
        digest: PlanDigest,
        offer: OfferIndex,
        additions: Vec<AdditionIndex>,
        subsets: Vec<Subset>,
    ) -> Self {
        Self {
            digest,
            offer,
            additions,
            subsets,
        }
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
    /// The plan's offer: its entries bind as the view showed them.
    pub(crate) offer: &'p Offer,
    /// The offer's members, in its order, each with the chosen candidates.
    pub(crate) members: Vec<Member>,
    /// The members of the chosen additions.
    pub(crate) added: Vec<Member>,
}

impl<'a> Planned<'a> {
    /// The offer `selection` chose in this plan, fulfilled as `fulfilment` says.
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: the digest of another plan; an unknown offer or addition; two
    /// additions of one optional set or answering one query; a subset of no `multiple` query
    /// or of one no chosen member answers, a second subset for one member, a subset refused, or
    /// one that drops a credential a transaction entry is bound to; or a background fulfilment
    /// of an offer that needs the wallet's display.
    pub fn choose(
        &self,
        selection: &Selection,
        fulfilment: Fulfilment,
    ) -> Result<Chosen<'_, 'a>, PresentationError> {
        if selection.digest != *self.view.digest() {
            return Err(PresentationError::DigestMismatch);
        }
        let view = self
            .view
            .offers()
            .get(selection.offer.value())
            .ok_or(PresentationError::OfferUnknown(selection.offer))?;
        let offer = view.offer();
        let additions = self.additions(offer, &selection.additions)?;
        let mut members = offer.members().to_vec();
        let mut added: Vec<Member> = additions
            .iter()
            .flat_map(|addition| addition.members().iter().cloned())
            .collect();
        for (at, subset) in selection.subsets.iter().enumerate() {
            if selection
                .subsets
                .iter()
                .take(at)
                .any(|s| s.query == subset.query)
            {
                return Err(PresentationError::SubsetRepeated(subset.query.clone()));
            }
            let query = self.multiple_query(&subset.query)?;
            let member = members
                .iter_mut()
                .chain(added.iter_mut())
                .find(|member| member.query() == query)
                .ok_or_else(|| PresentationError::SubsetMember(subset.query.clone()))?;
            *member = member.subset(&subset.positions)?;
        }
        self.keeps_bound_credentials(offer, &members)?;
        if fulfilment == Fulfilment::Background && view.wallet_display() == WalletDisplay::Needed {
            return Err(PresentationError::WalletDisplayNeeded);
        }
        Ok(Chosen {
            planned: self,
            offer,
            members,
            added,
        })
    }

    /// The additions of `offer` at `chosen`, at most one per optional set, none answering a
    /// query another answers (A3).
    fn additions<'o>(
        &self,
        offer: &'o Offer,
        chosen: &[AdditionIndex],
    ) -> Result<Vec<&'o Addition>, PresentationError> {
        let mut additions: Vec<&Addition> = Vec::with_capacity(chosen.len());
        for &index in chosen {
            let addition = offer
                .additions()
                .get(index.value())
                .ok_or(PresentationError::AdditionUnknown(index))?;
            if additions.iter().any(|a| a.set() == addition.set()) {
                return Err(PresentationError::AdditionSetRepeated(addition.set()));
            }
            let shared = addition.members().iter().find(|member| {
                additions
                    .iter()
                    .flat_map(|a| a.members())
                    .any(|other| other.query() == member.query())
            });
            if let Some(member) = shared {
                return Err(PresentationError::AdditionQueryRepeated(
                    self.query_id(member.query())?,
                ));
            }
            additions.push(addition);
        }
        Ok(additions)
    }

    /// The position of the `multiple` Credential Query `id`.
    fn multiple_query(&self, id: &QueryId) -> Result<QueryIndex, PresentationError> {
        self.answered
            .index_of(id.as_str())
            .filter(|&index| {
                self.answered
                    .answers(index)
                    .is_some_and(|answers| answers.query().multiple)
            })
            .ok_or_else(|| PresentationError::SubsetQuery(id.clone()))
    }

    /// Checks that every credential an entry of `offer` is bound to stays among `members`, so
    /// the binding of the chosen credentials is the plan's (T4).
    fn keeps_bound_credentials(
        &self,
        offer: &Offer,
        members: &[Member],
    ) -> Result<(), PresentationError> {
        for (bound, _) in self.transactions.bind(&self.answered, offer.members())? {
            let member = members
                .get(bound.member.value())
                .ok_or(Inconsistency::Member(bound.member))?;
            if !member.candidates().contains(&bound.candidate) {
                return Err(PresentationError::SubsetDropsEntry(
                    self.query_id(member.query())?,
                ));
            }
        }
        Ok(())
    }

    /// The `id` of the Credential Query at `index`.
    fn query_id(&self, index: QueryIndex) -> Result<QueryId, Inconsistency> {
        self.answered
            .answers(index)
            .map(|answers| answers.id().clone())
            .ok_or(Inconsistency::Query(index))
    }
}
