//! Transaction data in the plan (PaSO Core, Section 7.4): the wallet's sources, and the entries
//! a group of presented credentials binds (T4).

use std::convert::Infallible;

use itertools::Itertools;
use siros_credential::{EntryRef, UsableCredential};
use siros_dcql::QueryId;
use siros_transaction_data::{
    Context, Entry, Selection, SourceInputs, Taken, TransactionDataError,
};

use super::{PlanInput, Unproven};
use crate::error::Inconsistency;
use crate::ids::{CandidateIndex, QueryIndex};
use crate::matching::{Answered, Answers, Candidate};
use crate::offers::Member;
use crate::request::MatchRequest;
use crate::transactions::{Candidacy, TransactionSource, Transactions};

/// The presented credential a transaction entry binds to (T4): the Credential Query it answers,
/// and its entry, named by `credentialId` and instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Bound {
    pub(crate) query: QueryId,
    pub(crate) credential: EntryRef,
}

impl Bound {
    /// The credential `candidate` presented for the query of `answers`.
    pub(crate) fn of<C: crate::credential::MatchCredential, R>(
        answers: &Answers<'_, C, R>,
        candidate: &Candidate<C>,
    ) -> Self {
        Self {
            query: answers.id().clone(),
            credential: candidate.credential().entry(),
        }
    }
}

/// The answers of a request over the wallet's usable credentials.
pub(crate) type Wallet<'a> = Answered<'a, UsableCredential<'a>, Unproven>;

/// An entry a presented credential binds: the credential, the entry, and the view it took.
pub(crate) struct BoundEntry<'t> {
    pub(crate) bound: Bound,
    pub(crate) entry: &'t Entry,
    pub(crate) taken: &'t Taken,
}

/// The wallet's sources: the credential's own metadata, the configuration and the entry's ad-hoc
/// metadata, verified against the trust store and what the host holds.
impl<'a> TransactionSource<UsableCredential<'a>> for Context<'a> {
    type Deferral = Infallible;

    fn first_match(
        &self,
        entries: &[&Entry],
        credential: &UsableCredential<'a>,
    ) -> Result<Selection, TransactionDataError> {
        Context::first_match(self, entries, credential.credential())
    }

    fn knows(&self, entry: &Entry, credential: &UsableCredential<'a>) -> bool {
        Context::knows(self, entry, credential.credential())
    }
}

/// The context of `input`'s transaction data: the trust store, the metadata and display the
/// host holds, the configuration, the wallet's language, the time, and how the request reached
/// the wallet.
pub(crate) fn context<'a>(input: &PlanInput<'a>) -> Context<'a> {
    Context {
        sources: SourceInputs {
            trust: input.trust,
            held: input.held,
            display: input.display,
            configuration: input.configuration,
            language: input.language,
            now: input.now,
        },
        channel: input.request.channel(),
        signature: input.request.signature(),
    }
}

impl Transactions {
    /// The entries the presented credentials of `members` bind, one group (T4): each
    /// credential binds the entry it takes, and an entry two of them take binds to the one
    /// whose query comes first in its `credential_ids`, then the first presented (OpenID4VP
    /// 1.0, Section 5.1).
    ///
    /// # Errors
    ///
    /// [`Inconsistency`] for a member or a candidate the matching lacks.
    pub(crate) fn bind<'t>(
        &'t self,
        answered: &Wallet<'_>,
        members: &[Member],
    ) -> Result<Vec<BoundEntry<'t>>, Inconsistency> {
        let presented: Vec<(Bound, &'t Candidacy<Infallible>)> = offered(answered, members)?
            .iter()
            .flat_map(|member| {
                member
                    .candidates
                    .iter()
                    .filter_map(move |&(index, candidate)| {
                        let candidacy = self
                            .candidacies
                            .iter()
                            .find(|c| c.query == member.query && c.candidate == index)?;
                        Some((Bound::of(member.answers, candidate), candidacy))
                    })
            })
            .collect();
        let mut bound: Vec<BoundEntry<'t>> = Vec::new();
        for (credential, candidacy) in &presented {
            let Selection::Takes(taken) = &candidacy.selection else {
                continue;
            };
            let entry = self
                .entries
                .get(taken.entry().value())
                .ok_or(Inconsistency::Entry)?;
            let rank = |query: &QueryId| entry.credential_ids().iter().position(|id| id == query);
            let first = presented
                .iter()
                .filter(|(_, other)| matches!(&other.selection, Selection::Takes(t) if t.entry() == taken.entry()))
                .min_by_key(|(other, _)| rank(&other.query))
                .map(|(other, _)| other);
            if first == Some(credential) {
                bound.push(BoundEntry {
                    bound: credential.clone(),
                    entry,
                    taken,
                });
            }
        }
        Ok(bound)
    }
}

/// A member of an offer as the matching answers it: its query, and each of its candidates.
pub(crate) struct Offered<'w, 'a> {
    pub(crate) query: QueryIndex,
    pub(crate) answers: &'w Answers<'a, UsableCredential<'a>, Unproven>,
    pub(crate) candidates: Vec<(CandidateIndex, &'w Candidate<UsableCredential<'a>>)>,
}

impl<'a> Offered<'_, 'a> {
    /// Whether the entry of `bound` binds to the member's candidate `candidate`.
    pub(crate) fn carries(
        &self,
        bound: &Bound,
        candidate: &Candidate<UsableCredential<'a>>,
    ) -> bool {
        *bound == Bound::of(self.answers, candidate)
    }
}

/// Each member of `members` as the matching answers it, in order.
///
/// # Errors
///
/// [`Inconsistency`] for a member or a candidate the matching lacks.
pub(crate) fn offered<'w, 'a>(
    answered: &'w Wallet<'a>,
    members: &[Member],
) -> Result<Vec<Offered<'w, 'a>>, Inconsistency> {
    members
        .iter()
        .map(|member| {
            let query = member.query();
            let answers = answered.answers(query).ok_or(Inconsistency::Query(query))?;
            let candidates = member
                .candidates()
                .iter()
                .map(|&index| {
                    let candidate = answers
                        .candidate(index)
                        .ok_or(Inconsistency::Candidate(query, index))?;
                    Ok((index, candidate))
                })
                .try_collect()?;
            Ok(Offered {
                query,
                answers,
                candidates,
            })
        })
        .collect()
}
