//! The plan's digest (A4): SHA-256 of the canonical CBOR of the request and of every offer the
//! user can choose.

use sha2::{Digest, Sha256};
use siros_codec::cbor::Value;
use siros_dcql::PathComponent;
use siros_oid4vp::VerifiedRequest;

use super::view::{MemberView, OfferView};
use crate::display_rule::WalletDisplay;
use crate::matching::Answer;

/// The domain of the digest, which names this encoding.
const DOMAIN: &str = "siros-presentation plan 2";

/// The digest of the plan of `request`, whose nym_auth `verifier_id` is `verifier_id`, and
/// whose offers the user sees as `views`.
///
/// It covers the request's response mode, Client Identifier, trust verdict, origin, response
/// URI, `nonce`, `state`, `dcql_query` as sent, `transaction_data` and the nym_auth
/// `verifier_id`; and for each offer its members with every candidate's instance and answer
/// and the positions of the entries bound to it, its additions, and whether it needs the
/// wallet's display.
pub(crate) fn digest(
    request: &VerifiedRequest,
    verifier_id: Option<&str>,
    views: &[OfferView],
) -> [u8; 32] {
    let text = |t: Option<&str>| t.map_or(Value::Null, Value::text);
    let verifier = request.verifier();
    let request_part = Value::Array(vec![
        Value::text(request.response_mode().as_str()),
        text(verifier.client_id().map(|c| c.as_str())),
        Value::Bool(verifier.trusted()),
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
        text(verifier_id),
    ]);
    let offers = views
        .iter()
        .map(|view| {
            let additions = view
                .additions()
                .iter()
                .map(|addition| {
                    Value::Array(vec![
                        Value::Unsigned(addition.set() as u64),
                        members(addition.members()),
                    ])
                })
                .collect();
            Value::Array(vec![
                members(view.members()),
                Value::Array(additions),
                Value::Bool(view.wallet_display() == WalletDisplay::Needed),
            ])
        })
        .collect();
    let plan = Value::Array(vec![
        Value::text(DOMAIN),
        request_part,
        Value::Array(offers),
    ]);
    Sha256::digest(plan.encode()).into()
}

/// Each member's query id, and each of its credentials' instance, answer and bound entries.
fn members(members: &[MemberView]) -> Value {
    Value::Array(
        members
            .iter()
            .map(|member| {
                let credentials = member
                    .credentials()
                    .iter()
                    .map(|credential| {
                        let entries = credential
                            .entries()
                            .iter()
                            .map(|&e| Value::Unsigned(e as u64))
                            .collect();
                        Value::Array(vec![
                            Value::text(&credential.credential_id().to_string()),
                            answer(credential.answer()),
                            Value::Array(entries),
                        ])
                    })
                    .collect();
                Value::Array(vec![
                    Value::text(member.query_id()),
                    Value::Array(credentials),
                ])
            })
            .collect(),
    )
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
