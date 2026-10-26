//! The plan's digest (A4): SHA-256 of the canonical CBOR of the request and of every offer the
//! user can choose.

use sha2::{Digest, Sha256};
use siros_codec::cbor::Value;
use siros_dcql::PathComponent;
use siros_oid4vp::VerifiedRequest;

use super::transactions::Wallet;
use super::view::OfferView;
use crate::display_rule::WalletDisplay;
use crate::error::PresentationError;
use crate::matching::Answer;
use crate::offers::{Member, Offers};

/// The domain of the digest, which names this encoding.
const DOMAIN: &str = "siros-presentation plan 1";

/// The digest of the plan of `request`: the request's response target, `nonce`, `state`,
/// `dcql_query` as sent and `transaction_data`, and for each offer its members with their
/// instances and answers, its additions, the positions of the entries bound to each member, and
/// whether it needs the wallet's display.
pub(crate) fn digest(
    request: &VerifiedRequest,
    answered: &Wallet<'_>,
    offers: &Offers,
    views: &[OfferView],
) -> Result<[u8; 32], PresentationError> {
    let text = |t: Option<&str>| t.map_or(Value::Null, Value::text);
    let verifier = request.verifier();
    let request_part = Value::Array(vec![
        Value::text(request.response_mode().as_str()),
        text(verifier.client_id().map(|c| c.as_str())),
        text(request.origin()),
        text(request.response_uri().map(|u| u.as_str())),
        Value::text(request.nonce()),
        text(request.state()),
        Value::text(&request.dcql_query_json().to_string()),
        Value::Array(
            request
                .transaction_data()
                .iter()
                .map(|t| Value::text(t))
                .collect(),
        ),
    ]);
    let mut offer_parts = Vec::with_capacity(offers.offers().len());
    for (offer, view) in offers.offers().iter().zip(views) {
        let bound = view
            .members()
            .iter()
            .map(|member| {
                Value::Array(
                    member
                        .entries()
                        .iter()
                        .map(|&at| Value::Unsigned(at as u64))
                        .collect(),
                )
            })
            .collect();
        let additions = offer
            .additions()
            .iter()
            .map(|addition| {
                Ok(Value::Array(vec![
                    Value::Unsigned(addition.set() as u64),
                    members(answered, addition.members())?,
                ]))
            })
            .collect::<Result<_, PresentationError>>()?;
        offer_parts.push(Value::Array(vec![
            members(answered, offer.members())?,
            Value::Array(additions),
            Value::Array(bound),
            Value::Bool(view.wallet_display() == WalletDisplay::Needed),
        ]));
    }
    let plan = Value::Array(vec![
        Value::text(DOMAIN),
        request_part,
        Value::Array(offer_parts),
    ]);
    Ok(Sha256::digest(plan.encode()).into())
}

/// Each member's query id, instance and answer.
fn members(answered: &Wallet<'_>, members: &[Member]) -> Result<Value, PresentationError> {
    members
        .iter()
        .map(|member| {
            let answers = answered
                .queries()
                .get(member.query())
                .ok_or(PresentationError::AnswerMismatch)?;
            let candidate = answers
                .candidates()
                .get(member.candidate())
                .ok_or(PresentationError::AnswerMismatch)?;
            let entry = candidate.credential().credential().entry();
            Ok(Value::Array(vec![
                Value::text(&answers.query().id),
                Value::text(&entry.credential_id().to_string()),
                answer(candidate.answer()),
            ]))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn answer(answer: &Answer) -> Value {
    match answer {
        Answer::Claims(claims) => Value::Array(vec![
            Value::Unsigned(0),
            Value::Bool(claims.holder_binding()),
            Value::Array(
                claims
                    .pointers()
                    .iter()
                    .map(|pointer| {
                        Value::Array(pointer.components().iter().map(component).collect())
                    })
                    .collect(),
            ),
        ]),
        Answer::Proof(choice) => Value::Array(vec![
            Value::Unsigned(1),
            Value::Unsigned(choice.option() as u64),
            Value::text(choice.system().id()),
            Value::text(choice.backend()),
        ]),
    }
}

fn component(component: &PathComponent) -> Value {
    match component {
        PathComponent::Key(key) => Value::text(key),
        PathComponent::Index(index) => Value::Unsigned(*index),
        PathComponent::Null => Value::Null,
    }
}
