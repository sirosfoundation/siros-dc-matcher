//! Transaction data in the plan: the entries of the request, the type metadata of the
//! credentials they can bind to, and the binding of an offer (T4).

use siros_codec::date::DateTime;
use siros_credential::{Format, UsableCredential};
use siros_oid4vp::VerifiedRequest;
use siros_transaction_data::{
    bind, Entry, MemberBinding, Presented, ScaMetadata, Step, TransactionDataError,
};
use siros_wallet_state::CredentialId;

use super::fetches::Fetches;
use crate::error::PresentationError;
use crate::matching::Answered;
use crate::offers::Member;

/// The position of a member in its offer, and the index of one of its candidates.
pub(crate) type Bound = (usize, usize);

/// The answers of a request over the wallet's usable credentials.
pub(crate) type Wallet<'a> = Answered<'a, UsableCredential<'a>>;

/// The `transaction_data` entries of a request, and the SCA Attestation metadata of the
/// credentials that answer a query they name.
pub(crate) struct Transactions<'a> {
    entries: Vec<Entry>,
    metadata: Vec<(CredentialId, ScaMetadata<'a>)>,
}

impl<'a> Transactions<'a> {
    /// The entries of `request` at the time `now`, and the type metadata of each SD-JWT VC
    /// that answers a query an entry names, from `fetches`. The step is a fetch while the host
    /// has not given a document. A credential whose `vct` locates no type metadata authorizes
    /// no entry.
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
        let entries = request
            .transaction_data()
            .iter()
            .map(|raw| Entry::parse(raw, request.dcql_query(), now))
            .collect::<Result<Vec<_>, _>>()
            .map_err(PresentationError::TransactionData)?;
        let named: Vec<usize> = answered
            .queries()
            .iter()
            .enumerate()
            .filter(|(_, answers)| {
                entries
                    .iter()
                    .any(|e| e.credential_ids().contains(&answers.query().id))
            })
            .map(|(index, _)| index)
            .collect();
        let mut metadata: Vec<(CredentialId, ScaMetadata<'a>)> = Vec::new();
        let mut judged: Vec<CredentialId> = Vec::new();
        let credentials = named
            .iter()
            .filter_map(|&query| answered.queries().get(query))
            .flat_map(|answers| answers.candidates())
            .map(|candidate| candidate.credential().credential())
            .filter(|credential| credential.format() == Format::SdJwtVc);
        for credential in credentials {
            let id = credential.entry().credential_id();
            if judged.contains(&id) {
                continue;
            }
            judged.push(id);
            let Ok(fetch) = ScaMetadata::fetch(credential) else {
                continue;
            };
            let Some(response) = fetches.response(&fetch) else {
                return Ok(Step::Fetch(fetch));
            };
            let read = ScaMetadata::parse(credential, response)
                .map_err(PresentationError::TransactionData)?;
            metadata.push((id, read));
        }
        Ok(Step::Done(Self { entries, metadata }))
    }

    /// Whether an entry names only Credential Queries no credential answers: its credentials are
    /// not available in the wallet (Section 8.5).
    pub(crate) fn unavailable(&self, answered: &Wallet<'a>) -> bool {
        self.entries.iter().any(|entry| {
            entry.credential_ids().iter().all(|id| {
                answered
                    .queries()
                    .iter()
                    .filter(|answers| &answers.query().id == id)
                    .all(|answers| answers.candidates().is_empty())
            })
        })
    }

    /// The positions in the request's `transaction_data` of the entries `binding` binds.
    pub(crate) fn positions(
        &self,
        binding: &MemberBinding<'_, '_>,
    ) -> Result<Vec<usize>, TransactionDataError> {
        binding
            .entries()
            .iter()
            .map(|bound| {
                self.entries
                    .iter()
                    .position(|entry| std::ptr::eq(entry, *bound))
                    .ok_or(TransactionDataError::CredentialUnavailable)
            })
            .collect()
    }

    /// For each entry, the indexes of the Credential Queries its `credential_ids` name.
    pub(crate) fn named(&self, answered: &Wallet<'a>) -> Vec<Vec<usize>> {
        self.entries
            .iter()
            .map(|entry| {
                answered
                    .queries()
                    .iter()
                    .enumerate()
                    .filter(|(_, answers)| entry.credential_ids().contains(&answers.query().id))
                    .map(|(index, _)| index)
                    .collect()
            })
            .collect()
    }

    /// The entries bound to the credentials of the offer of `members`, each binding with the
    /// position of its member and the index of its candidate. A request without entries binds
    /// none; a credential without type metadata authorizes none.
    ///
    /// # Errors
    ///
    /// [`PresentationError::TransactionData`] when no credential of the offer authorizes an
    /// entry, or the entries bound to one credential share no hash algorithm, and
    /// [`PresentationError::AnswerMismatch`] for a member the matching lacks.
    pub(crate) fn bind<'t>(
        &'t self,
        answered: &Wallet<'a>,
        members: &[Member],
    ) -> Result<Vec<(Bound, MemberBinding<'t, 't>)>, PresentationError> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }
        let mut presented: Vec<(Bound, Presented<'t>)> = Vec::new();
        for (at, member) in members.iter().enumerate() {
            let answers = answered
                .queries()
                .get(member.query())
                .ok_or(PresentationError::AnswerMismatch)?;
            for &index in member.candidates() {
                let candidate = answers
                    .candidates()
                    .get(index)
                    .ok_or(PresentationError::AnswerMismatch)?;
                let id = candidate.credential().credential().entry().credential_id();
                if let Some((_, metadata)) = self.metadata.iter().find(|(m, _)| *m == id) {
                    presented.push(((at, index), Presented::new(&answers.query().id, metadata)));
                }
            }
        }
        let offer: Vec<Presented<'t>> = presented.iter().map(|(_, p)| *p).collect();
        let fail = PresentationError::TransactionData;
        bind(&self.entries, &offer)
            .map_err(fail)?
            .into_iter()
            .map(|binding| {
                let bound = binding.presented();
                let at = presented
                    .iter()
                    .find_map(|(at, p)| {
                        let same = p.query_id() == bound.query_id()
                            && p.credential().entry() == bound.credential().entry();
                        same.then_some(*at)
                    })
                    .ok_or(fail(TransactionDataError::CredentialUnavailable))?;
                Ok((at, binding))
            })
            .collect()
    }
}
