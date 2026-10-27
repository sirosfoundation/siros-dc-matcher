//! The `transaction_data` entries as the offers see them (A3, T4): the Credential Queries each
//! names, and the candidates whose credentials can carry it.

use siros_dcql::QueryId;

use super::Member;
use crate::credential::MatchCredential;
use crate::ids::{CandidateIndex, QueryIndex};
use crate::matching::{Answered, Answers, Candidate};

/// The Credential Queries a `transaction_data` entry names in its `credential_ids`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryQueries(Vec<QueryIndex>);

/// A candidate of a Credential Query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Carrier {
    query: QueryIndex,
    candidate: CandidateIndex,
}

/// A `transaction_data` entry: the Credential Queries it names, and the candidates of those
/// whose credentials can carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCarriers {
    queries: EntryQueries,
    carriers: Vec<Carrier>,
}

impl<'r, C: MatchCredential, R> Answered<'r, C, R> {
    /// The Credential Queries of the request whose `id` an entry `names`.
    pub fn entry_queries(&self, mut names: impl FnMut(&QueryId) -> bool) -> EntryQueries {
        EntryQueries(
            self.indexed()
                .filter(|(_, answers)| names(answers.id()))
                .map(|(query, _)| query)
                .collect(),
        )
    }
}

impl EntryQueries {
    /// The positions of the Credential Queries.
    pub fn queries(&self) -> &[QueryIndex] {
        &self.0
    }

    /// Whether the entry names `query`.
    pub fn names(&self, query: QueryIndex) -> bool {
        self.0.contains(&query)
    }

    /// The entry with its carriers among `answered`'s candidates of the queries it names: those
    /// `carries` accepts.
    pub fn carriers<'r, C: MatchCredential, R>(
        self,
        answered: &Answered<'r, C, R>,
        mut carries: impl FnMut(&Answers<'r, C, R>, &Candidate<C>) -> bool,
    ) -> EntryCarriers {
        let carriers = answered
            .indexed()
            .filter(|(query, _)| self.names(*query))
            .flat_map(|(query, answers)| {
                answers
                    .candidates()
                    .iter()
                    .enumerate()
                    .map(move |(at, candidate)| {
                        (query, answers, CandidateIndex::new(at), candidate)
                    })
            })
            .filter(|(_, answers, _, candidate)| carries(answers, candidate))
            .map(|(query, _, candidate, _)| Carrier { query, candidate })
            .collect();
        EntryCarriers {
            queries: self,
            carriers,
        }
    }
}

impl EntryCarriers {
    /// Whether the entry names `query`.
    pub(super) fn names(&self, query: QueryIndex) -> bool {
        self.queries.names(query)
    }

    /// Whether a member of `members` presents a credential that can carry the entry.
    pub(super) fn carried_by(&self, members: &[Member]) -> bool {
        members.iter().any(|member| self.carries(member))
    }

    /// Whether `member` presents a credential that can carry the entry.
    pub(super) fn carries(&self, member: &Member) -> bool {
        member.candidates.iter().any(|&candidate| {
            self.carriers.contains(&Carrier {
                query: member.query,
                candidate,
            })
        })
    }
}
