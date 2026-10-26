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

/// The answers of a request over the wallet's usable credentials.
pub(crate) type Wallet<'a> = Answered<'a, 'a, UsableCredential<'a>>;

/// The `transaction_data` entries of a request, and the SCA Attestation metadata of the
/// credentials that answer a query they name.
pub(crate) struct Transactions<'a> {
    entries: Vec<Entry>,
    named: Vec<usize>,
    metadata: Vec<(CredentialId, ScaMetadata<'a>)>,
}

impl<'a> Transactions<'a> {
    /// The entries of `request` at the time `now`, and the type metadata of each SD-JWT VC
    /// that answers a query an entry names, from `fetches`. The step is a fetch while the host
    /// has not given a document. A credential whose metadata does not fetch or read authorizes
    /// no entry.
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
            if let Ok(read) = ScaMetadata::parse(credential, response) {
                metadata.push((id, read));
            }
        }
        Ok(Step::Done(Self {
            entries,
            named,
            metadata,
        }))
    }

    /// The entries, in the order of the request.
    pub(crate) fn entries(&self) -> &[Entry] {
        &self.entries
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

    /// Whether an entry names the Credential Query at `query` in its `credential_ids`.
    pub(crate) fn names(&self, query: usize) -> bool {
        self.named.contains(&query)
    }

    /// The entries bound to the credentials of the offer of `members`, each binding with the
    /// index of its member. A request without entries binds none.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`] when no credential of the offer authorizes an entry, or the
    /// entries bound to one credential share no hash algorithm.
    pub(crate) fn bind<'t>(
        &'t self,
        answered: &Wallet<'a>,
        members: &[Member],
    ) -> Result<Vec<(usize, MemberBinding<'t, 't>)>, TransactionDataError> {
        if self.entries.is_empty() {
            return Ok(Vec::new());
        }
        let presented: Vec<(usize, Presented<'t>)> = members
            .iter()
            .enumerate()
            .filter_map(|(at, member)| {
                let answers = answered.queries().get(member.query())?;
                let credential = answers.candidates().get(member.candidate())?.credential();
                let id = credential.credential().entry().credential_id();
                let (_, metadata) = self.metadata.iter().find(|(m, _)| *m == id)?;
                Some((at, Presented::new(&answers.query().id, metadata)))
            })
            .collect();
        let offer: Vec<Presented<'t>> = presented.iter().map(|(_, p)| *p).collect();
        bind(&self.entries, &offer)?
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
                    .ok_or(TransactionDataError::CredentialUnavailable)?;
                Ok((at, binding))
            })
            .collect()
    }
}
