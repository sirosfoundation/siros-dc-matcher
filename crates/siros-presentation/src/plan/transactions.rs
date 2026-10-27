//! Transaction data in the plan (PaSO Core, Section 7.4): the entries of the request, the entry
//! each candidate takes or why it takes none, and the entries a group of presented credentials
//! binds (T4).

use itertools::Itertools;
use siros_credential::{Credential, EntryRef, UsableCredential};
use siros_dcql::QueryId;
use siros_transaction_data::{
    check_request, fetched, Context, Entry, EntryPosition, Exclusion, Selection, Step, Taken,
    TransactionDataError,
};

use super::{PlanInput, Unproven};
use crate::error::{Inconsistency, PresentationError};
use crate::ids::{CandidateIndex, QueryIndex};
use crate::matching::{Answered, Answers, Candidate};
use crate::offers::Member;

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

/// A candidate of a targeted query, its credential, and what it takes.
struct Candidacy<'a> {
    query: QueryIndex,
    candidate: CandidateIndex,
    credential: &'a Credential,
    selection: Selection,
}

impl Candidacy<'_> {
    /// The credential and why it takes no entry, when the first match excluded it.
    fn exclusion(&self) -> Option<Exclusion> {
        match &self.selection {
            Selection::Excluded(causes) => Some(Exclusion {
                credential: self.credential.entry(),
                causes: causes.clone(),
            }),
            Selection::Takes(_) => None,
        }
    }
}

/// The `transaction_data` entries of a request, and the selection of each candidate of a
/// query they target.
pub(crate) struct Transactions<'a> {
    entries: Vec<Entry>,
    candidacies: Vec<Candidacy<'a>>,
}

/// An entry a presented credential binds: the credential, the entry, and the view it took.
pub(crate) struct BoundEntry<'t> {
    pub(crate) bound: Bound,
    pub(crate) entry: &'t Entry,
    pub(crate) taken: &'t Taken,
}

impl<'a> Transactions<'a> {
    /// The entries of `input`'s request and the first match of each candidate of `answered`
    /// whose query an entry targets (PaSO Core, Sections 7.4.1 and 7.4.2). The step is a fetch
    /// while the host has not given a document.
    ///
    /// # Errors
    ///
    /// [`PresentationError::TransactionData`]: an entry that does not read; credential sets
    /// that break Section 7.4.1; an unsigned request a PaSO type or source needs signed; a type
    /// no source defines for any candidate, unless the first match serves every credential the
    /// entry targets (OpenID4VP 1.0, Section 5.1); or no compatible candidate left.
    pub(crate) fn read(
        input: &PlanInput<'a>,
        answered: &Wallet<'a>,
    ) -> Result<Step<Self>, PresentationError> {
        let request = input.request;
        let entries: Vec<Entry> = request
            .transaction_data()
            .iter()
            .enumerate()
            .map(|(at, raw)| {
                let position = EntryPosition::new(at);
                Entry::parse(position, raw, request.dcql_query())
                    .map_err(|refusal| TransactionDataError::Entry(position, refusal))
            })
            .try_collect()?;
        check_request(&entries, request.dcql_query(), request.signature())?;
        let context = Context {
            trust: input.trust,
            held: input.held,
            fetched: input.fetches.fetched(),
            display: input.display,
            configuration: input.configuration,
            language: input.language,
            signature: request.signature(),
            now: input.now,
        };
        let mut candidacies = Vec::new();
        for (query, answers) in answered.indexed() {
            let targeting: Vec<&Entry> = entries.iter().filter(|e| e.names(answers.id())).collect();
            if targeting.is_empty() {
                continue;
            }
            for (at, candidate) in answers.candidates().iter().enumerate() {
                let credential = candidate.credential().credential();
                let selection = fetched!(context.first_match(&targeting, credential)?);
                candidacies.push(Candidacy {
                    query,
                    candidate: CandidateIndex::new(at),
                    credential,
                    selection,
                });
            }
        }
        let transactions = Self {
            entries,
            candidacies,
        };
        transactions.known(answered, &context)?;
        transactions.compatible_left()?;
        Ok(Step::Done(transactions))
    }

    /// Checks each entry whose type the wallet knows from no source for any candidate it
    /// targets: the first match then serves every such candidate (OpenID4VP 1.0, Section 5.1;
    /// PaSO Core, Section 7.4.2).
    fn known(
        &self,
        answered: &Wallet<'_>,
        context: &Context<'a>,
    ) -> Result<(), TransactionDataError> {
        for entry in &self.entries {
            let targets: Vec<&Candidacy> = self
                .candidacies
                .iter()
                .filter(|c| {
                    answered
                        .answers(c.query)
                        .is_some_and(|a| entry.names(a.id()))
                })
                .collect();
            let served = targets
                .iter()
                .all(|c| matches!(c.selection, Selection::Takes(_)));
            if served {
                continue;
            }
            if !targets
                .iter()
                .any(|target| context.knows(entry, target.credential))
            {
                let exclusions = targets.iter().filter_map(|c| c.exclusion()).collect();
                return Err(TransactionDataError::TypeUnknown(
                    entry.position(),
                    exclusions,
                ));
            }
        }
        Ok(())
    }

    /// Checks that a candidate takes an entry when some candidate is targeted (PaSO Core,
    /// Section 7.4.2, step 4).
    fn compatible_left(&self) -> Result<(), TransactionDataError> {
        if self.candidacies.is_empty()
            || self
                .candidacies
                .iter()
                .any(|c| matches!(c.selection, Selection::Takes(_)))
        {
            return Ok(());
        }
        Err(TransactionDataError::NoCompatibleCredential(
            self.candidacies
                .iter()
                .filter_map(Candidacy::exclusion)
                .collect(),
        ))
    }

    /// Whether `candidate` of `query` may be offered: it takes an entry, or no entry targets
    /// its query.
    pub(crate) fn eligible(&self, query: QueryIndex, candidate: CandidateIndex) -> bool {
        !self.candidacies.iter().any(|c| {
            c.query == query
                && c.candidate == candidate
                && matches!(c.selection, Selection::Excluded(_))
        })
    }

    /// Whether the request carries entries and none of the queries they target has a
    /// candidate: the referenced credentials are not available (OpenID4VP 1.0, Section 8.5).
    pub(crate) fn unavailable(&self) -> bool {
        !self.entries.is_empty() && self.candidacies.is_empty()
    }

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
        let presented: Vec<(Bound, &'t Candidacy<'a>)> = offered(answered, members)?
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
