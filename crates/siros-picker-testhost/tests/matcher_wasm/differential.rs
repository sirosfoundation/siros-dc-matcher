//! The picker against the wallet (K2): for the same request, credentials, metadata, trust store
//! and time, `matcher.wasm` over the registration the wallet writes offers what the wallet's plan
//! offers, with the same credentials, titles, issuer lines, rows, transactions, purposes and
//! delegation. Where the wallet's plan reads what the registration leaves out, the picker offers
//! more, and the wallet decides. Every run keeps the host's rules: one declaration per set id, and a null
//! pointer for an absent subtitle, disclaimer or warning.

use serde_json::Value;
use siros_picker_testhost::Captured;
use siros_presentation::testing::wallet::{ready, Wallet};
use siros_presentation::{Exclusion, Failure, PresentationError};
use siros_registration::CredentialIcon;

use crate::sides::{
    intake, picker_offers, picker_run, registration, wallet_offers, Offered, LEVELS,
};
use crate::{corpus, families, key_free, paso};

/// A request over a wallet, and what the picker cannot verify of it.
pub struct Case {
    pub name: String,
    /// The DC API request, as the browser sends it.
    pub request: Vec<u8>,
    /// The request's `transaction_data` entries, decoded.
    pub entries: Vec<Value>,
    pub wallet: Wallet,
    /// The images the host rendered for the credentials' cards.
    pub icons: Vec<CredentialIcon>,
    /// Where the wallet's plan reads what the registration leaves out.
    pub exception: Option<Exception>,
}

/// What the registration leaves out (K2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exception {
    /// A `zkp_req` credential test that reads an undisclosable attribute, or the seed (N3, N4).
    CredentialTests,
    /// An entry's ad-hoc metadata JWT.
    AdHocMetadata,
    /// The `semantic` form of the nym_auth `verifier_id`, the owner's K2 exception: its
    /// identifier comes from the access certificate's DER, which the projection leaves out.
    SemanticVerifierId,
    /// Which signature of a multisigned request qualifies, which decides its Verifier metadata
    /// and `verifier_info`: the owner's K2 exception, as only the signatures' verification
    /// tells.
    MixedSigners,
    /// The purpose of an offer a payment entry shows, which the wallet configuration maps to a
    /// payment entry's fields in a later wave: the picker's payment entry shows none.
    PaymentPurpose,
}

#[test]
fn the_picker_offers_what_the_wallet_plans() {
    let cases: Vec<Case> = corpus::cases()
        .into_iter()
        .chain(paso::cases())
        .chain(families::cases())
        .chain(key_free::cases())
        .collect();
    let disagreements: Vec<String> = cases
        .iter()
        .flat_map(|case| LEVELS.map(|level| (case, level)))
        .filter_map(|(case, level)| {
            compare(case, level)
                .err()
                .map(|why| format!("{} at level {level}: {why}", case.name))
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "{} of {} cases disagree:\n{}",
        disagreements.len(),
        cases.len() * LEVELS.len(),
        disagreements.join("\n")
    );
}

/// What the picker, for a host at `level`, and the wallet offer for `case` agree: equal
/// offers; or, under an exception, each of the wallet's offers shown alike by one of more of the
/// picker's.
fn compare(case: &Case, level: u32) -> Result<(), String> {
    let request = intake(&case.request);
    let planned = request
        .as_ref()
        .map(|request| ready(&case.wallet.input(request)));
    let wallet = match &planned {
        Some(Ok(planned)) => wallet_offers(planned.view(), &case.entries, level),
        Some(Err(_)) | None => Vec::new(),
    };
    let captured = picker_run(
        &case.request,
        registration(&case.wallet, &case.icons),
        level,
    );
    host_rules(&captured)?;
    let picker = picker_offers(&captured, level);
    let exception = case.exception.or_else(|| match &planned {
        Some(Err(refusal)) if unproven(refusal) => Some(Exception::CredentialTests),
        _ => None,
    });
    match exception {
        None | Some(Exception::PaymentPurpose) => {
            let wallet = match exception {
                Some(Exception::PaymentPurpose) => without_purpose(wallet),
                _ => wallet,
            };
            if picker != wallet {
                return Err(format!("wallet {wallet:#?}\npicker {picker:#?}"));
            }
            Ok(())
        }
        Some(exception) => {
            let unmatched: Vec<&Offered> = wallet
                .iter()
                .filter(|offer| !picker.iter().any(|shown| shows(shown, offer)))
                .collect();
            if !unmatched.is_empty() || picker.len() <= wallet.len() {
                return Err(format!(
                    "{exception:?}: wallet {unmatched:#?} not shown alike among more of picker \
                     {picker:#?}"
                ));
            }
            Ok(())
        }
    }
}

/// `offers` with no purpose: what the picker shows of an offer whose entries are payment entries.
fn without_purpose(offers: Vec<Offered>) -> Vec<Offered> {
    offers
        .into_iter()
        .map(|offer| Offered {
            purpose: None,
            ..offer
        })
        .collect()
}

/// Whether the picker's offer `shown` shows the wallet's offer `offer` alike under a K2
/// exception: the same queries and purpose, each of the wallet's credentials presented as the
/// wallet presents it, and the same delegation when it presents the same credentials. The
/// picker may present more credentials of a query, which the wallet decides after the pick.
fn shows(shown: &Offered, offer: &Offered) -> bool {
    let queries = |offered: &Offered| -> Vec<String> {
        offered
            .members
            .iter()
            .map(|(query, _)| query.clone())
            .collect()
    };
    if queries(shown) != queries(offer) || shown.purpose != offer.purpose {
        return false;
    }
    let presented = offer
        .members
        .iter()
        .zip(&shown.members)
        .all(|((_, wallet), (_, picker))| wallet.iter().all(|p| picker.contains(p)));
    let same = credentials(std::slice::from_ref(shown)) == credentials(std::slice::from_ref(offer));
    presented && (!same || shown.background == offer.background)
}

/// Whether the wallet refuses with no offer because every credential of a query fails the
/// `zkp_req` credential tests or opens no seed (N3, N4): what the registration leaves out.
fn unproven(refusal: &PresentationError) -> bool {
    match refusal {
        PresentationError::NoOffer(Failure::Excluded { reasons, .. }) => reasons
            .iter()
            .all(|reason| matches!(reason, Exclusion::Unproven(_))),
        _ => false,
    }
}

/// Whether `captured` keeps the rules a device showed: a set id declared twice discards the
/// whole output, and an empty disclaimer or warning draws an empty badge.
fn host_rules(captured: &Captured) -> Result<(), String> {
    let mut ids: Vec<&str> = captured.sets.iter().map(|(id, _)| id.as_str()).collect();
    ids.sort_unstable();
    if let Some(pair) = ids.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(format!("the set id {} is declared twice", pair[0]));
    }
    let empty = |text: &Option<String>| text.as_deref() == Some("");
    match captured
        .entries
        .iter()
        .find(|entry| empty(&entry.subtitle) || empty(&entry.disclaimer) || empty(&entry.warning))
    {
        Some(entry) => Err(format!("an empty string for an absent line: {entry:?}")),
        None => Ok(()),
    }
}

/// The credentials of each member of each offer.
fn credentials(offers: &[Offered]) -> Vec<Vec<(String, Vec<u64>)>> {
    offers
        .iter()
        .map(|offer| {
            offer
                .members
                .iter()
                .map(|(query, presented)| {
                    let ids = presented.iter().map(|p| p.credential).collect();
                    (query.clone(), ids)
                })
                .collect()
        })
        .collect()
}
