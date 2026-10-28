//! A registration holds no delivered or derived secret and no undisclosable attribute of a
//! nym_auth attestation (R-G6; nym_auth catalogue §9.5: `ssc`, `psc`, `secret_seed`,
//! `birth_date`, and the auxiliary data that opens the commitments).

use siros_codec::base64url;
use siros_codec::cbor::{self, Item, Kind};
use siros_codec::date::DateTime;
use siros_display::{CardText, CardWording};
use siros_presentation::testing::verifier::NOW;
use siros_presentation::testing::wallet::{nym_auth, Held, Wallet};
use siros_registration::{write, Diagnostics, RasterIcon, RegistrationInput};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::testing::{Spec, SEED};

/// Every text and byte string of `item`.
fn strings<'a>(item: &Item<'a>, texts: &mut Vec<&'a str>, bytes: &mut Vec<&'a [u8]>) {
    match item.kind() {
        Kind::Text(text) => texts.push(text),
        Kind::Bytes(data) => bytes.push(data),
        Kind::Array(items) => items.iter().for_each(|item| strings(item, texts, bytes)),
        Kind::Map(members) => members.iter().for_each(|(key, value)| {
            strings(key, texts, bytes);
            strings(value, texts, bytes);
        }),
        Kind::Tag(_, inner) => strings(inner, texts, bytes),
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
    let item = cbor::decode(&registration).unwrap();
    let (mut texts, mut bytes) = (Vec::new(), Vec::new());
    strings(&item, &mut texts, &mut bytes);
    assert!(
        texts.contains(&"eu.europa.ec.eudi.nym_auth.1"),
        "the registration holds the attestation's claims: {texts:?}"
    );
    for name in ["ssc", "psc", "secret_seed", "birth_date"] {
        assert!(!texts.contains(&name), "{name} in {texts:?}");
    }
    let opening = base64url::encode(&SEED).into_string();
    assert!(
        !texts.iter().any(|text| text.contains(&opening)),
        "the seed's opening"
    );
    assert!(
        !bytes
            .iter()
            .any(|data| data.windows(SEED.len()).any(|w| w == SEED)),
        "the seed"
    );
}
