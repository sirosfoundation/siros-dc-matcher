//! A registration holds no delivered or derived secret and no undisclosable attribute of a
//! nym_auth attestation (R-G6; nym_auth catalogue §9.5: `ssc`, `psc`, `secret_seed`,
//! `birth_date`, and the auxiliary data that opens the commitments).

use std::io::Cursor;

use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_dcql::PathComponent;
use siros_display::{CardText, CardWording};
use siros_presentation::testing::verifier::NOW;
use siros_presentation::testing::wallet::{nym_auth, Held, Wallet};
use siros_registration::{write, Diagnostics, RasterIcon, Registration, RegistrationInput};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::testing::{Spec, SEED};

/// Every text of `value`.
fn texts(value: &Cbor, found: &mut Vec<String>) {
    match value {
        Cbor::Text(text) => found.push(text.clone()),
        Cbor::Array(items) => items.iter().for_each(|item| texts(item, found)),
        Cbor::Map(members) => members.iter().for_each(|(key, value)| {
            texts(key, found);
            texts(value, found);
        }),
        Cbor::Tag(_, inner) => texts(inner, found),
        _ => {}
    }
}

#[test]
fn a_nym_registration_holds_no_secret_and_no_undisclosable_attribute() {
    let (data, auxiliary) = nym_auth(&Spec::default());
    let mut held = Held::new(1, "mso_mdoc", data);
    held.metadata = Some(auxiliary);
    let mut wallet = Wallet::new(vec![held]);
    wallet.systems = NymAuthSystem::ALL.to_vec();
    let png = [
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".as_slice(),
        &64u32.to_be_bytes(),
        &64u32.to_be_bytes(),
        &[8, 2, 0, 0, 0],
    ]
    .concat();
    let registration = write(&RegistrationInput {
        credentials: &wallet.credentials,
        records: wallet.records(),
        display: &wallet.display,
        language: &wallet.language,
        card_wording: &CardWording {
            title: CardText::new("Credential").unwrap(),
            issuer: CardText::new("Unknown issuer").unwrap(),
            issuer_template: None,
        },
        held: &wallet.metadata,
        configuration: &wallet.configuration,
        trust: &wallet.trust,
        systems: &wallet.systems,
        verifier_id: wallet.verifier_id,
        background: &wallet.background,
        icons: &[],
        default_icon: &RasterIcon::parse(png).unwrap(),
        diagnostics: Diagnostics::Hidden,
        now: DateTime::from_unix(NOW).unwrap(),
    })
    .unwrap();
    let projection = Registration::open(Cursor::new(registration.as_slice()))
        .unwrap()
        .projection()
        .unwrap();
    let mut found = Vec::new();
    for credential in projection.credentials() {
        texts(&credential.claims().to_cbor(), &mut found);
        let labels = credential.labels();
        for label in labels.types().iter().chain(labels.issuer()) {
            found.extend(label.path().components().iter().filter_map(|c| match c {
                PathComponent::Key(key) => Some(key.clone()),
                PathComponent::Index(_) | PathComponent::Null => None,
            }));
        }
    }
    assert!(
        found
            .iter()
            .any(|text| text == "eu.europa.ec.eudi.nym_auth.1"),
        "the registration holds the attestation's claims: {found:?}"
    );
    for name in ["ssc", "psc", "secret_seed", "birth_date"] {
        assert!(
            !found.iter().any(|text| text == name),
            "{name} in {found:?}"
        );
    }
    let opening = base64url::encode(&SEED).into_string();
    let holds = |needle: &[u8]| registration.windows(needle.len()).any(|w| w == needle);
    assert!(!holds(opening.as_bytes()), "the seed's opening");
    assert!(!holds(&SEED), "the seed");
}
