//! The picker against the wallet (K2): for the same request, credentials, metadata, trust store
//! and time, `matcher.wasm` over the registration the wallet writes offers what the wallet's plan
//! offers, with the same credentials, titles, rows, transactions, purposes and delegation, and
//! the picks of each offer's entries select that offer in the plan (K3). Where the wallet's plan
//! reads what the registration leaves out, the picker offers more, and the wallet decides.

use serde_json::Value;
use siros_presentation::testing::wallet::{ready, Wallet};
use siros_presentation::{Exclusion, Failure, Fetches, PresentationError};
use siros_registration::CredentialIcon;

use crate::sides::{
    chosen_through_picks, intake, picker_offers, picker_run, proof_queries, registration,
    wallet_offers, Offered,
};
use crate::{corpus, paso};

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
    /// An image at an `https` URL (T6).
    RemoteImage,
    /// An entry's ad-hoc metadata JWT.
    AdHocMetadata,
}

#[test]
fn the_picker_offers_what_the_wallet_plans() {
    let cases: Vec<Case> = corpus::cases().into_iter().chain(paso::cases()).collect();
    let disagreements: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            compare(case)
                .err()
                .map(|why| format!("{}: {why}", case.name))
        })
        .collect();
    assert!(
        disagreements.is_empty(),
        "{} of {} cases disagree:\n{}",
        disagreements.len(),
        cases.len(),
        disagreements.join("\n")
    );
}

/// What the picker and the wallet offer for `case` agree: equal offers, each chosen through
/// its picks; or, under an exception, the wallet's offers among more of the picker's.
fn compare(case: &Case) -> Result<(), String> {
    let request = intake(&case.request);
    let fetches = match &request {
        Some(request) => case.wallet.fetches(request),
        None => Fetches::new(),
    };
    let planned = request
        .as_ref()
        .map(|request| ready(&case.wallet.input(request, &fetches)));
    let (wallet, proofs) = match &planned {
        Some(Ok(planned)) => (
            wallet_offers(planned.view(), &case.entries),
            proof_queries(planned.view()),
        ),
        Some(Err(_)) | None => (Vec::new(), Vec::new()),
    };
    let captured = picker_run(&case.request, registration(&case.wallet, &case.icons));
    let picker = picker_offers(&captured, &proofs);
    let exception = case.exception.or_else(|| match &planned {
        Some(Err(refusal)) if unproven(refusal) => Some(Exception::CredentialTests),
        _ => None,
    });
    match exception {
        None => {
            if picker != wallet {
                return Err(format!("wallet {wallet:#?}\npicker {picker:#?}"));
            }
            if let Some(Ok(planned)) = &planned {
                if let Some(offer) =
                    (0..picker.len()).find(|&at| !chosen_through_picks(planned, &captured, at))
                {
                    return Err(format!("the picks of offer {offer} select nothing"));
                }
            }
            Ok(())
        }
        Some(exception) => {
            let (wallet, picker) = (credentials(&wallet), credentials(&picker));
            let among = wallet.iter().all(|offer| picker.contains(offer));
            if among && picker.len() > wallet.len() {
                Ok(())
            } else {
                Err(format!(
                    "{exception:?}: wallet {wallet:?} not among more of picker {picker:?}"
                ))
            }
        }
    }
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
