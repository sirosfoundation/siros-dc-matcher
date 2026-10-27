//! The presentation component's matching over the request and the registration (K2), and the
//! entry set of each offer.

use android_credman::SetSink;
use siros_oid4vp::{diagnose, Protocol, UnverifiedRequest};
use siros_presentation::{Asked, Matching, NoOffer, ProofChoice, Transactions, ZkpQuery};
use siros_registration::{RegisteredCredential, Registration, Unverified};
use siros_zkp_req_nym_auth::policy::signed_and_encrypted;

use crate::diagnostics::Unshown;
use crate::entries::OfferEntries;

/// Why a `zkp_req` candidate answers no option in the picker: its query has none with a usable
/// pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NoChoice;

/// Emits the entry set of each offer of `request` over `registration` to `sets`, for a host at
/// `level`, and gives why it emitted none, or which offers it could not show.
///
/// The request is the first entry of the DC API request under a protocol of OpenID4VP 1.0,
/// A.1. Its `zkp_req` candidates answer the first option with a usable pair: the credential
/// tests and the seed are the wallet's (N3, N4). Its issuers are admitted from the facts the
/// wallet registered (TR5), at the registration's time.
pub(crate) fn pick(
    request: &[u8],
    registration: &Registration,
    level: u32,
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
        signed_and_encrypted(&request).map(drop),
    );
    let answered = matching.answer(|_, _, zkp: &ZkpQuery| first_choice(zkp));
    if let Some(failure) = answered.invalid_request() {
        return vec![Unshown::Refused(failure.code())];
    }
    let source = Unverified::new(registration, request.signature());
    let transactions = match Transactions::read(&request, &answered, &source) {
        Ok(transactions) => transactions,
        Err(error) => return vec![Unshown::TransactionData(error.code())],
    };
    let offers = match transactions.offers(&answered) {
        Ok(offers) => offers,
        Err(NoOffer::CredentialUnavailable) => return vec![Unshown::CredentialUnavailable],
        Err(NoOffer::Unmatched(failure)) => return vec![Unshown::Unmatched(failure.code())],
    };
    let shown = OfferEntries::sources(&answered, &transactions, level);
    offers
        .offers()
        .iter()
        .enumerate()
        .filter_map(|(at, offer)| shown.emit(at, offer, sets).err())
        .collect()
}

/// The first option of `zkp` with a usable pair: the picker applies no credential test.
fn first_choice(zkp: &ZkpQuery) -> Result<ProofChoice, NoChoice> {
    zkp.choices().first().cloned().ok_or(NoChoice)
}
