//! The selection the user makes by picking credential picker entries (K3).

use siros_dcql::QueryId;
use siros_wallet_state::CredentialId;

use super::selection::{Selection, Subset};
use crate::error::{Inconsistency, PresentationError};
use crate::ids::{AdditionIndex, OfferIndex, QueryIndex};
use crate::offers::{Addition, Member};
use crate::plan::Planned;

/// A credential picker entry the user picked, by the ids its metadata carries (K3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pick {
    offer: OfferIndex,
    query: QueryId,
    credential: CredentialId,
}

impl Pick {
    /// The entry of the credential `credential` answering the Credential Query `query` in the
    /// offer `offer`.
    pub fn new(offer: OfferIndex, query: QueryId, credential: CredentialId) -> Self {
        Self {
            offer,
            query,
            credential,
        }
    }
}

/// Why the picked entries make no selection (K3).
#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum PickError {
    /// The user picked no entry.
    Empty,
    /// The picks name two offers: the first pick's, then this one.
    Offers(OfferIndex, OfferIndex),
    /// Two picks name this credential for this Credential Query.
    Repeated {
        /// The Credential Query.
        query: QueryId,
        /// The credential.
        credential: CredentialId,
    },
    /// No member of the offer or of its additions answers this Credential Query.
    Query(QueryId),
    /// No member of the offer or of its additions answers this Credential Query with this
    /// credential.
    Credential {
        /// The Credential Query.
        query: QueryId,
        /// The credential.
        credential: CredentialId,
    },
    /// No pick names a credential of the offer's member of this Credential Query.
    Missing(QueryId),
    /// No additions of the offer, at most one per optional set, answer exactly the picked
    /// queries the offer's members leave.
    Additions,
}

impl PickError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "pick_empty",
            Self::Offers(..) => "pick_offers",
            Self::Repeated { .. } => "pick_repeated",
            Self::Query(_) => "pick_query_unknown",
            Self::Credential { .. } => "pick_credential_unknown",
            Self::Missing(_) => "pick_member_missing",
            Self::Additions => "pick_additions",
        }
    }
}

/// The credentials the picks name for one Credential Query, in the order of the picks.
struct Picked {
    query: QueryIndex,
    id: QueryId,
    credentials: Vec<CredentialId>,
}

impl Picked {
    /// Checks that `held` holds each picked credential.
    fn held_in(&self, held: &[CredentialId]) -> Result<(), PickError> {
        match self.credentials.iter().find(|id| !held.contains(id)) {
            Some(&credential) => Err(PickError::Credential {
                query: self.id.clone(),
                credential,
            }),
            None => Ok(()),
        }
    }
}

impl Planned<'_> {
    /// The selection the user made by picking `picks` (K3): the offer they name, with the
    /// additions whose members they name, and for each `multiple` member the picked
    /// credentials.
    ///
    /// When several combinations of additions answer the picked queries, the first in the
    /// offer's order is chosen: each presents the picked credentials.
    ///
    /// # Errors
    ///
    /// [`PresentationError::Pick`]: no pick; picks of two offers; a pick repeated; a pick no
    /// member of the offer or of its additions holds; an offer member without a pick; or picked
    /// queries no combination of additions answers. [`PresentationError::OfferUnknown`] for an
    /// offer the plan lacks.
    pub fn picked(&self, picks: &[Pick]) -> Result<Selection, PresentationError> {
        let first = picks.first().ok_or(PickError::Empty)?;
        if let Some(other) = picks.iter().find(|pick| pick.offer != first.offer) {
            return Err(PickError::Offers(first.offer, other.offer).into());
        }
        let repeated = picks
            .iter()
            .enumerate()
            .find(|&(at, pick)| picks.iter().take(at).any(|other| other == pick));
        if let Some((_, pick)) = repeated {
            return Err(PickError::Repeated {
                query: pick.query.clone(),
                credential: pick.credential,
            }
            .into());
        }
        let offer = self
            .view
            .offers()
            .get(first.offer.value())
            .ok_or(PresentationError::OfferUnknown(first.offer))?
            .offer();
        let picked = self.by_query(picks)?;
        let mut subsets = Vec::new();
        for member in offer.members() {
            let named = match picked.iter().find(|picked| picked.query == member.query()) {
                Some(named) => named,
                None => return Err(PickError::Missing(self.query_id(member.query())).into()),
            };
            named.held_in(&self.ids([member])?)?;
            subsets.extend(self.subset(named));
        }
        let left: Vec<&Picked> = picked
            .iter()
            .filter(|picked| offer.members().iter().all(|m| m.query() != picked.query))
            .collect();
        let additions: Vec<(AdditionIndex, &Addition)> = offer
            .additions()
            .iter()
            .enumerate()
            .map(|(at, addition)| (AdditionIndex::new(at), addition))
            .collect();
        for named in &left {
            self.held_by_additions(&additions, named)?;
            subsets.extend(self.subset(named));
        }
        let mut fitting: Vec<(AdditionIndex, &Addition)> = Vec::new();
        for (index, addition) in additions {
            if self.fits(addition, &left)? {
                fitting.push((index, addition));
            }
        }
        let mut queries: Vec<QueryIndex> = left.iter().map(|picked| picked.query).collect();
        queries.sort_unstable();
        let mut chosen = cover(&fitting, &queries).ok_or(PickError::Additions)?;
        chosen.sort_unstable();
        Ok(Selection::new(
            *self.view.digest(),
            first.offer,
            chosen,
            subsets,
        ))
    }

    /// The picks of `picks` grouped by Credential Query, in the order of their first pick.
    fn by_query(&self, picks: &[Pick]) -> Result<Vec<Picked>, PickError> {
        let mut picked: Vec<Picked> = Vec::new();
        for pick in picks {
            match picked.iter_mut().find(|picked| picked.id == pick.query) {
                Some(same) => same.credentials.push(pick.credential),
                None => picked.push(Picked {
                    query: self
                        .answered
                        .index_of(&pick.query)
                        .ok_or_else(|| PickError::Query(pick.query.clone()))?,
                    id: pick.query.clone(),
                    credentials: vec![pick.credential],
                }),
            }
        }
        Ok(picked)
    }

    /// The `credentialId`s of the candidates of `members`.
    ///
    /// # Errors
    ///
    /// [`Inconsistency`] when a member names a query or a candidate the matching lacks.
    fn ids<'m>(
        &self,
        members: impl IntoIterator<Item = &'m Member>,
    ) -> Result<Vec<CredentialId>, Inconsistency> {
        let mut ids = Vec::new();
        for member in members {
            ids.extend(self.held(member)?.into_iter().map(|(_, id)| id));
        }
        Ok(ids)
    }

    /// Checks that the members of `additions` that answer the query of `picks` hold each of its
    /// credentials.
    fn held_by_additions(
        &self,
        additions: &[(AdditionIndex, &Addition)],
        picks: &Picked,
    ) -> Result<(), PresentationError> {
        let members: Vec<&Member> = additions
            .iter()
            .flat_map(|(_, addition)| addition.members())
            .filter(|member| member.query() == picks.query)
            .collect();
        if members.is_empty() {
            return Err(PickError::Query(picks.id.clone()).into());
        }
        Ok(picks.held_in(&self.ids(members)?)?)
    }

    /// Whether the picks `left` name a credential of each member of `addition`, and only
    /// credentials the member holds for its query.
    ///
    /// # Errors
    ///
    /// [`Inconsistency`] when a member names a query or a candidate the matching lacks.
    fn fits(&self, addition: &Addition, left: &[&Picked]) -> Result<bool, Inconsistency> {
        for member in addition.members() {
            let Some(picks) = left.iter().find(|picked| picked.query == member.query()) else {
                return Ok(false);
            };
            if picks.held_in(&self.ids([member])?).is_err() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The subset of `picks` when they answer a `multiple` Credential Query.
    ///
    /// # Panics
    ///
    /// When the matching has no query at the position of `picks`.
    #[expect(
        clippy::expect_used,
        reason = "`by_query` takes the position of picks from the matching; another one is a \
                  bug of the core, and no selection built on it is sound"
    )]
    fn subset(&self, picks: &Picked) -> Option<Subset> {
        let answers = self
            .answered
            .answers(picks.query)
            .expect("the picks of a query name a query of the matching");
        answers
            .query()
            .multiple
            .then(|| Subset::new(picks.id.clone(), picks.credentials.clone()))
    }
}

/// The additions among `fitting` that answer each query of `queries`, in the request's order,
/// once, at most one per optional set: the first such combination in the order of `fitting`.
fn cover(
    fitting: &[(AdditionIndex, &Addition)],
    queries: &[QueryIndex],
) -> Option<Vec<AdditionIndex>> {
    let Some(&first) = queries.first() else {
        return Some(Vec::new());
    };
    fitting
        .iter()
        .filter(|(_, addition)| {
            let answers = |query| addition.members().iter().any(|m| m.query() == query);
            answers(first)
                && addition
                    .members()
                    .iter()
                    .all(|m| queries.contains(&m.query()))
        })
        .find_map(|&(index, addition)| {
            let rest: Vec<QueryIndex> = queries
                .iter()
                .copied()
                .filter(|&query| addition.members().iter().all(|m| m.query() != query))
                .collect();
            let others: Vec<(AdditionIndex, &Addition)> = fitting
                .iter()
                .copied()
                .filter(|(_, other)| other.set() != addition.set())
                .collect();
            let mut chosen = cover(&others, &rest)?;
            chosen.push(index);
            Some(chosen)
        })
}
