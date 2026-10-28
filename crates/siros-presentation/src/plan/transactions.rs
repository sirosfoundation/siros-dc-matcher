//! Transaction data in the plan: the entries of the request, the type metadata of the
//! credentials they can bind to, and the binding of an offer (T4).

use itertools::Itertools;
use siros_codec::date::DateTime;
use siros_credential::{Credential, EntryRef, Format, Instance, UsableCredential};
use siros_dcql::QueryId;
use siros_oid4vp::VerifiedRequest;
use siros_transaction_data::{
    bind, Entry, MemberBinding, Presented, ScaMetadata, Step, TransactionDataError,
};
use siros_wallet_state::CredentialId;

use super::fetches::Fetches;
use super::Unproven;
use crate::error::{Inconsistency, PresentationError};
use crate::ids::{position, CandidateIndex, QueryIndex};
use crate::matching::{Answered, Answers, Candidate};
use crate::offers::{EntryCarriers, EntryQueries, Member};

position!(
    /// The position of an entry in the request's `transaction_data`.
    EntryPosition
);

/// The presented credential a transaction entry binds to (T4): the Credential Query it answers,
/// and its entry, named by `credentialId` and instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Bound {
    pub(crate) query: QueryId,
    pub(crate) credential: EntryRef,
}

impl Bound {
    /// The credential `candidate` presented for the query of `answers`.
    pub(crate) fn of<C: Instance, R>(
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

/// The `transaction_data` entries of a request, and the SCA Attestation metadata of the
/// credentials that answer a query they name.
pub(crate) struct Transactions<'a> {
    entries: Vec<Entry>,
    metadata: Vec<(CredentialId, ScaMetadata<'a>)>,
}

impl<'a> Transactions<'a> {
    /// The entries of `request` at the time `now`, and the type metadata of each SD-JWT VC
    /// that answers a query an entry names, from `fetches`. The step is a fetch while the host
    /// has not given a document. A credential whose `vct` is no `https` URL locates no type
    /// metadata, and authorizes no entry (EC TS12 v1.0.1, Section 4.1.1).
    ///
    /// # Errors
    ///
    /// [`PresentationError::TransactionData`] for an entry that breaks its rules, and for a
    /// fetched type metadata document that does not read: its status, its `vct`, its integrity
    /// or its shape.
    pub(crate) fn read(
        request: &VerifiedRequest,
        answered: &Wallet<'a>,
        fetches: &Fetches,
        now: DateTime,
    ) -> Result<Step<Self>, PresentationError> {
        let entries: Vec<Entry> = request
            .transaction_data()
            .iter()
            .map(|raw| Entry::parse(raw, request.dcql_query(), now))
            .try_collect()?;
        let mut metadata = Vec::new();
        for credential in authorizing(answered, &entries) {
            let fetch = match ScaMetadata::fetch(credential) {
                Ok(fetch) => fetch,
                Err(TransactionDataError::VctNotHttps) => continue,
                Err(error) => return Err(error.into()),
            };
            let response = fetched!(fetches
                .response(&fetch)
                .map_or(Step::Fetch(fetch.clone()), Step::Done));
            let read = ScaMetadata::parse(credential, response)?;
            metadata.push((credential.entry().credential_id(), read));
        }
        Ok(Step::Done(Self { entries, metadata }))
    }

    /// Checks that each entry names a Credential Query some credential answers.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::CredentialUnavailable`] for an entry whose credentials are not
    /// available in the wallet (Section 8.5).
    pub(crate) fn available(&self, answered: &Wallet<'a>) -> Result<(), TransactionDataError> {
        let unavailable = self.entries.iter().any(|entry| {
            let named = named(answered, entry);
            answered
                .indexed()
                .filter(|(query, _)| named.names(*query))
                .all(|(_, answers)| answers.candidates().is_empty())
        });
        if unavailable {
            return Err(TransactionDataError::CredentialUnavailable);
        }
        Ok(())
    }

    /// The positions in the request's `transaction_data` of the entries `binding` binds.
    ///
    /// # Errors
    ///
    /// [`Inconsistency::Entry`] for an entry of other transactions than these.
    pub(crate) fn positions(
        &self,
        binding: &MemberBinding<'_, '_>,
    ) -> Result<Vec<EntryPosition>, Inconsistency> {
        binding
            .entries()
            .iter()
            .map(|bound| {
                self.entries
                    .iter()
                    .position(|entry| std::ptr::eq(entry, *bound))
                    .map(EntryPosition::at)
                    .ok_or(Inconsistency::Entry)
            })
            .collect()
    }

    /// Each entry with the candidates that can carry it: those answering a query it names whose
    /// type metadata authorizes its type.
    pub(crate) fn carriers(&self, answered: &Wallet<'a>) -> Vec<EntryCarriers> {
        self.entries
            .iter()
            .map(|entry| {
                named(answered, entry).carriers(answered, |answers, candidate| {
                    self.metadata_of(candidate).is_some_and(|metadata| {
                        entry.carried_by(&Presented::new(answers.id(), metadata))
                    })
                })
            })
            .collect()
    }

    /// The SCA Attestation metadata of `candidate`'s credential; none when its `vct` locates
    /// none.
    fn metadata_of(&self, candidate: &Candidate<UsableCredential<'a>>) -> Option<&ScaMetadata<'a>> {
        let id = candidate.credential().credential().entry().credential_id();
        self.metadata
            .iter()
            .find(|(credential, _)| *credential == id)
            .map(|(_, metadata)| metadata)
    }

    /// The entries bound to the credentials of the offer of `members`, each binding with the
    /// credential it binds to. A request without entries binds none; a credential without
    /// type metadata authorizes none.
    ///
    /// # Errors
    ///
    /// [`PresentationError::TransactionData`] when no credential of the offer authorizes an
    /// entry, or the entries bound to one credential share no hash algorithm, and
    /// [`PresentationError::Inconsistent`] for a member the matching lacks or a binding to a
    /// credential outside the offer.
    pub(crate) fn bind<'t>(
        &'t self,
        answered: &Wallet<'a>,
        members: &[Member],
    ) -> Result<Vec<(Bound, MemberBinding<'t, 't>)>, PresentationError> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }
        // A credential without type metadata authorizes no entry.
        let offered = offered(answered, members)?;
        let presented: Vec<(Bound, Presented<'t>)> = offered
            .iter()
            .flat_map(|member| {
                member.candidates.iter().filter_map(|&(_, candidate)| {
                    let metadata = self.metadata_of(candidate)?;
                    let bound = Bound::of(member.answers, candidate);
                    Some((bound, Presented::new(&member.answers.query().id, metadata)))
                })
            })
            .collect();
        let offer: Vec<Presented<'t>> = presented.iter().map(|(_, p)| *p).collect();
        bind(&self.entries, &offer)?
            .into_iter()
            .map(|binding| {
                let credential = binding.presented();
                let bound = presented
                    .iter()
                    .find(|(_, p)| {
                        p.query_id() == credential.query_id()
                            && p.credential().entry() == credential.credential().entry()
                    })
                    .map(|(bound, _)| bound.clone())
                    .ok_or(Inconsistency::BoundCredential)?;
                Ok((bound, binding))
            })
            .collect()
    }
}

/// The Credential Queries `entry` names among `answered`'s.
fn named(answered: &Wallet<'_>, entry: &Entry) -> EntryQueries {
    answered.entry_queries(|id| entry.names(id))
}

/// The SD-JWT VCs that answer a query an entry of `entries` names, each once.
fn authorizing<'w, 'a: 'w>(
    answered: &'w Wallet<'a>,
    entries: &'w [Entry],
) -> impl Iterator<Item = &'a Credential> + 'w {
    let named: Vec<EntryQueries> = entries.iter().map(|e| named(answered, e)).collect();
    let mut seen: Vec<CredentialId> = Vec::new();
    answered
        .indexed()
        .filter(move |(query, _)| named.iter().any(|entry| entry.names(*query)))
        .flat_map(|(_, answers)| answers.candidates())
        .map(|candidate| candidate.credential().credential())
        .filter(|credential| credential.format() == Format::SdJwtVc)
        .filter(move |credential| {
            let id = credential.entry().credential_id();
            let first = !seen.contains(&id);
            if first {
                seen.push(id);
            }
            first
        })
}

/// A member of an offer as the matching answers it: its query, the query's answers, and each
/// of its candidates.
pub(crate) struct Offered<'w, 'a> {
    pub(crate) query: QueryIndex,
    pub(crate) answers: &'w Answers<'a, UsableCredential<'a>, Unproven>,
    pub(crate) candidates: Vec<(CandidateIndex, &'w Candidate<UsableCredential<'a>>)>,
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
                .collect::<Result<_, Inconsistency>>()?;
            Ok(Offered {
                query,
                answers,
                candidates,
            })
        })
        .collect()
}
