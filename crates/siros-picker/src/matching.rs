//! The presentation component's matching over the request and the registration (K2), and the
//! entry set of each offer.

use std::io::{Read, Seek};

use android_credman::SetSink;
use siros_oid4vp::{diagnose, Protocol, UnverifiedRequest};
use siros_presentation::{
    Asked, Matching, NoOffer, OfferIndex, ProofChoice, RequestEntries, Transactions, ZkpQuery,
};
use siros_registration::{Registration, Unverified};
use siros_zkp_req_nym_auth::policy::admitted;

use crate::candidates::{self, Requested};
use crate::diagnostics::Unshown;
use crate::entries::OfferEntries;
use crate::shown::{Matched, ShownOffer};
use crate::Input;

/// Why a `zkp_req` candidate answers no option in the picker: its query has none with a usable
/// pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NoChoice;

/// Emits the entry set of each offer of the request of `input` over `registration` to `sets`,
/// for the host level of `input`, and gives why it emitted none, or which offers it could not
/// show. The offers that show are numbered in order, as the wallet's plan numbers its views.
///
/// The request is the first entry of the DC API request under a protocol of OpenID4VP 1.0,
/// A.1. The registration gives the credentials of the types its queries ask for, the
/// definitions its entries name for them, and the icons of the entries emitted. Its `zkp_req`
/// candidates answer the first option with a usable pair: the credential tests and the seed are
/// the wallet's (N3, N4). Its issuers are admitted from the facts the wallet registered (TR5),
/// at the registration's time. A nym_auth request meets the policy and the `verifier_id` rule of
/// the wallet's form as the plan applies them.
pub(crate) fn pick<R: Read + Seek>(
    input: &Input<'_>,
    registration: &mut Registration<R>,
    sets: &mut impl SetSink,
) -> Vec<Unshown> {
    let known = |label: &str| Protocol::from_label(label).is_some();
    let Some(request) = UnverifiedRequest::first_registered(input.request, &known) else {
        return vec![Unshown::Request(diagnose(input.request, &known))];
    };
    let asked = Asked::of(&request);
    let entries = RequestEntries::read(&request);
    let credentials = match candidates::read(registration, &asked.types(), entries.as_ref().ok()) {
        Ok(credentials) => credentials,
        Err(error) => return vec![Unshown::Registration(error.code())],
    };
    let credentials: Vec<&Requested> = credentials.iter().collect();
    let facts = registration.facts();
    let matching = Matching::new(
        asked,
        &credentials,
        &(),
        &[],
        facts.systems(),
        facts.registered_at().date(),
        admitted(&request, facts.verifier_id()).map(drop),
    );
    let answered = matching.answer(|_, _, zkp: &ZkpQuery| first_choice(zkp));
    if let Some(failure) = answered.invalid_request() {
        return vec![Unshown::Refused(failure.code())];
    }
    let source = Unverified::new(facts, &request);
    let selected = entries.and_then(|entries| Transactions::select(entries, &answered, &source));
    let transactions = match selected {
        Ok(transactions) => transactions,
        Err(error) => return vec![Unshown::TransactionData(error.code())],
    };
    let offers = match transactions.offers(&answered) {
        Ok(offers) => offers,
        Err(NoOffer::CredentialUnavailable) => return vec![Unshown::CredentialUnavailable],
        Err(NoOffer::Unmatched(failure)) => return vec![Unshown::Unmatched(failure.code())],
    };
    let matched = Matched {
        answered: &answered,
        transactions: &transactions,
    };
    let mut unshown = Vec::new();
    let mut shown = Vec::new();
    for (index, offer) in offers.offers().iter().enumerate() {
        match matched.shown(OfferIndex::new(index), offer) {
            Ok(presented) => shown.push(ShownOffer {
                offer,
                credentials: presented,
            }),
            Err(reason) => unshown.push(reason),
        }
    }
    let shown = match shown
        .into_iter()
        .map(|offer| offer.with_icons(registration))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(shown) => shown,
        Err(error) => return vec![Unshown::Registration(error.code())],
    };
    let entries = OfferEntries {
        transactions: &transactions,
        level: input.level,
    };
    for (at, offer) in shown.iter().enumerate() {
        entries.emit(OfferIndex::new(at), offer, sets);
    }
    unshown
}

/// The first option of `zkp` with a usable pair: the picker applies no credential test.
fn first_choice(zkp: &ZkpQuery) -> Result<ProofChoice, NoChoice> {
    zkp.choices().first().cloned().ok_or(NoChoice)
}
