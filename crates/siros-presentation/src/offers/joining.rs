//! The proposals of an enumeration (A3): the base proposals, and the optional sets joined to
//! each that leaves a transaction entry uncarried, every proposal spending the examination
//! budget.

use serde_json::Value;
use siros_dcql::Dropped;

use super::choices::sum;
use super::{Combination, EntryCarriers, Member, OptionalSet, MAX_EXAMINED};

/// A combination the enumeration proposes as an offer.
pub(super) struct Proposal<'s> {
    pub(super) purposes: Vec<Value>,
    pub(super) members: Combination,
    /// The optional sets left for joining and for additions.
    pub(super) others: Vec<&'s OptionalSet>,
}

/// A proposal whose choices answer each query once.
pub(super) struct Agreed<'s> {
    pub(super) purposes: Vec<Value>,
    pub(super) members: Vec<Member>,
    /// The optional sets left for joining and for additions.
    pub(super) others: Vec<&'s OptionalSet>,
}

impl<'s> Proposal<'s> {
    /// The proposal when its choices agree.
    fn agreed(self) -> Option<Agreed<'s>> {
        Some(Agreed {
            purposes: self.purposes,
            members: self.members.agreed()?,
            others: self.others,
        })
    }
}

impl<'s> Agreed<'s> {
    /// The proposal with `choice`, an option of the optional set `set`, joined as members; `None`
    /// when the option answers a query of the proposal with another candidate.
    fn joining(&self, set: &OptionalSet, choice: Vec<Member>) -> Option<Self> {
        let members = Combination::of(vec![self.members.clone(), choice]).agreed()?;
        let purposes = self
            .purposes
            .iter()
            .chain(set.choices.purpose())
            .cloned()
            .collect();
        let others = self
            .others
            .iter()
            .copied()
            .filter(|other| other.index != set.index)
            .collect();
        Some(Self {
            purposes,
            members,
            others,
        })
    }
}

/// A proposal that leaves an entry uncarried, and the options of its optional sets that carry
/// the first such entry.
struct Frame<'s> {
    proposal: Agreed<'s>,
    /// How many entries the proposal leaves uncarried.
    uncarried: usize,
    /// The options not yet joined, with their sets.
    joins: Box<dyn Iterator<Item = (&'s OptionalSet, Vec<Member>)> + 's>,
    /// How many options are not yet joined; `None` when it overflows.
    left: Option<usize>,
    /// How many proposals the enumeration had given when the frame began.
    given: usize,
}

impl<'s> Frame<'s> {
    /// The frame of `proposal`, which leaves `uncarried` entries uncarried, `entry` the first.
    fn of(proposal: Agreed<'s>, entry: &EntryCarriers, uncarried: usize, given: usize) -> Self {
        let sets: Vec<_> = proposal
            .others
            .iter()
            .map(|&set| (set, set.choices.carrying(|member| entry.carries(member))))
            .collect();
        let left = sum(sets.iter().map(|(_, carrying)| carrying.count));
        let joins = sets
            .into_iter()
            .flat_map(|(set, carrying)| carrying.choices.map(move |choice| (set, choice)));
        Self {
            proposal,
            uncarried,
            joins: Box::new(joins),
            left,
            given,
        }
    }
}

/// The proposals of an enumeration that carry every entry, depth first: each base proposal,
/// and for one that leaves an entry uncarried, each option of its optional sets that carries
/// the first such entry joined, repeated until every entry is carried. At most one option of
/// each set joins. A proposal no join completes is dropped.
///
/// Each base proposal and each join spends one of [`MAX_EXAMINED`].
pub(super) struct Joining<'s, 'e, B> {
    bases: B,
    /// How many base proposals there are; `None` when it overflows.
    total: Option<usize>,
    taken: usize,
    entries: &'e [EntryCarriers],
    frames: Vec<Frame<'s>>,
    examined: usize,
    given: usize,
    dropped: bool,
}

impl<'s, 'e, B: Iterator<Item = Proposal<'s>>> Joining<'s, 'e, B> {
    /// The proposals of `bases`, `total` of them, for the entries `entries`.
    pub(super) fn new(bases: B, total: Option<usize>, entries: &'e [EntryCarriers]) -> Self {
        Self {
            bases,
            total,
            taken: 0,
            entries,
            frames: Vec::new(),
            examined: 0,
            given: 0,
            dropped: false,
        }
    }

    /// Whether a proposal was dropped because no join lets it carry every entry.
    pub(super) fn dropped(&self) -> bool {
        self.dropped
    }

    /// How many proposals were not examined. The count is a lower bound while a base proposal
    /// or a join that may leave an entry uncarried is left.
    pub(super) fn unexamined(&self) -> Dropped {
        let bases = self.total.map(|total| total.saturating_sub(self.taken));
        let left = sum(std::iter::once(bases).chain(self.frames.iter().map(|f| f.left)));
        let leaves = self.frames.iter().all(|frame| frame.uncarried == 1);
        let exact = leaves && (self.entries.is_empty() || bases == Some(0));
        match left {
            Some(left) if exact => Dropped::Exact(left),
            Some(left) => Dropped::AtLeast(left),
            None => Dropped::AtLeast(usize::MAX.saturating_sub(self.examined)),
        }
    }

    /// The next proposal to examine: the next join of the innermost frame, else the next base
    /// proposal. `None` when the enumeration is over; `Some(None)` for choices that disagree.
    fn next_examined(&mut self) -> Option<Option<Agreed<'s>>> {
        loop {
            let Some(frame) = self.frames.last_mut() else {
                let base = self.bases.next()?;
                self.taken += 1;
                return Some(base.agreed());
            };
            if let Some((set, choice)) = frame.joins.next() {
                frame.left = frame.left.map(|left| left.saturating_sub(1));
                return Some(frame.proposal.joining(set, choice));
            }
            if let Some(done) = self.frames.pop() {
                self.dropped |= done.given == self.given;
            }
        }
    }
}

impl<'s, B: Iterator<Item = Proposal<'s>>> Iterator for Joining<'s, '_, B> {
    type Item = Agreed<'s>;

    fn next(&mut self) -> Option<Agreed<'s>> {
        while self.examined < MAX_EXAMINED {
            let examined = self.next_examined()?;
            self.examined += 1;
            let Some(proposal) = examined else {
                continue;
            };
            let entries = self.entries;
            let uncarried = |entry: &&EntryCarriers| !entry.carried_by(&proposal.members);
            let Some(entry) = entries.iter().find(uncarried) else {
                self.given += 1;
                return Some(proposal);
            };
            let count = entries.iter().filter(uncarried).count();
            self.frames
                .push(Frame::of(proposal, entry, count, self.given));
        }
        None
    }
}
