//! The presentation component's matching over the request and the registration (K2), and the
//! entry set of each offer.

use android_credman::SetSink;
use siros_oid4vp::{diagnose, Protocol, UnverifiedRequest};
use siros_presentation::{
    Asked, Matching, NoOffer, OfferIndex, ProofChoice, Transactions, ZkpQuery,
};
use siros_registration::{RegisteredCredential, Registration, Unverified};
use siros_zkp_req_nym_auth::policy::admitted;

use crate::diagnostics::Unshown;
use crate::entries::{HostLevel, OfferEntries};
use crate::shown::Matched;

/// Why a `zkp_req` candidate answers no option in the picker: its query has none with a usable
/// pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NoChoice;

/// Emits the entry set of each offer of `request` over `registration` to `sets`, for a host at
/// `level`, and gives why it emitted none, or which offers it could not show. The offers that
/// show are numbered in order, as the wallet's plan numbers its views.
///
/// The request is the first entry of the DC API request under a protocol of OpenID4VP 1.0,
/// A.1. Its `zkp_req` candidates answer the first option with a usable pair: the credential
/// tests and the seed are the wallet's (N3, N4). Its issuers are admitted from the facts the
/// wallet registered (TR5), at the registration's time. A nym_auth request meets the policy and
/// the `verifier_id` rule of the wallet's form as the plan applies them.
pub(crate) fn pick(
    request: &[u8],
    registration: &Registration,
    level: HostLevel,
    sets: &mut impl SetSink,
) -> Vec<Unshown> {
    let known = |label: &str| Protocol::from_label(label).is_some();
    let Some(request) = UnverifiedRequest::first_registered(request, &known) else {
        return vec![Unshown::Request(diagnose(request, &known))];
    };
    let credentials: Vec<&RegisteredCredential> = registration.credentials().iter().collect();
    let matching = Matching::new(
        Asked::of(&request),
        &credentials,
        &(),
        &[],
        registration.systems(),
        registration.registered_at().date(),
        admitted(&request, registration.verifier_id()).map(drop),
    );
    let answered = matching.answer(|_, _, zkp: &ZkpQuery| first_choice(zkp));
    if let Some(failure) = answered.invalid_request() {
        return vec![Unshown::Refused(failure.code())];
    }
    let source = Unverified::new(registration, &request);
    let transactions = match Transactions::read(&request, &answered, &source) {
        Ok(transactions) => transactions,
        Err(error) => return vec![Unshown::TransactionData(error.code())],
    };
    let offers = match transactions.offers(&answered) {
        Ok(offers) => offers,
        Err(NoOffer::CredentialUnavailable) => return vec![Unshown::CredentialUnavailable],
        Err(NoOffer::Unmatched(failure)) => return vec![Unshown::Unmatched(failure.code())],
    };
    let entries = OfferEntries {
        matched: Matched {
            answered: &answered,
            transactions: &transactions,
        },
        level,
    };
    let mut unshown = Vec::new();
    let mut at = 0;
    for (index, offer) in offers.offers().iter().enumerate() {
        match entries.matched.shown(OfferIndex::new(index), offer) {
            Ok(presented) => {
                entries.emit(OfferIndex::new(at), offer, &presented, sets);
                at += 1;
            }
            Err(reason) => unshown.push(reason),
        }
    }
    unshown
}

/// The first option of `zkp` with a usable pair: the picker applies no credential test.
fn first_choice(zkp: &ZkpQuery) -> Result<ProofChoice, NoChoice> {
    zkp.choices().first().cloned().ok_or(NoChoice)
}
