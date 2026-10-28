//! The writer's round trip: writing a projection, then reading it back, whole and by type,
//! gives the projection again, and equal projections give equal bytes. The projections are
//! drawn at random from fixed seeds.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::io::Cursor;

use serde_json::json;
use siros_codec::cbor::{self, Value as Cbor};
use siros_codec::date::DateTime;
use siros_credential::{ClaimTree, EntryRef, Format};
use siros_dcql::{AuthorityValue, ClaimPath, PathComponent};
use siros_display::{CardText, ClaimLabels, DescribedLabel, LabelText, Locale};
use siros_presentation::{KeyHolding, Presentability};
use siros_transaction_data::{Projected, ServedTypes, TypeId};
use siros_trust::{IssuerFacts, KeyIdentifier, StoreAuthority, StoreType};
use siros_wallet_state::{BatchId, CredentialId, InstanceId};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;

use crate::encode::encode;
use crate::reader::Registration;
use crate::registration::{
    Diagnostics, Facts, Icon, Projection, RegisteredCard, RegisteredCredential, RegisteredType,
};
use crate::wire::UNSERVED;

/// The projections drawn.
const DRAWS: u64 = 64;

/// SplitMix64: a seeded generator of the draws.
struct Draw(u64);

impl Draw {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn bytes(&mut self, most: usize) -> Vec<u8> {
        (0..=self.below(most)).map(|_| self.next() as u8).collect()
    }
}

/// The types the credentials are drawn from: both formats, names that share a prefix, and a
/// name outside ASCII.
const TYPES: [(Format, &str); 7] = [
    (Format::SdJwtVc, "https://credentials.example/pid"),
    (Format::SdJwtVc, "https://credentials.example/pid-2"),
    (Format::SdJwtVc, "https://bank.example/sca/card"),
    (Format::SdJwtVc, "urn:example:ålder"),
    (Format::Mdoc, "org.iso.18013.5.1.mDL"),
    (Format::Mdoc, "eu.europa.ec.eudi.pid.1"),
    (Format::Mdoc, "eu.europa.ec.eudi.pid.1.extra"),
];

const NAMES: [&str; 8] = [
    "given_name",
    "family_name",
    "age_over_18",
    "address",
    "nationalities",
    "portrait",
    "birth_place",
    "ünïcode",
];

const LANGUAGES: [&str; 3] = ["en", "sv", "de-AT"];

fn projection(seed: u64) -> Projection {
    let mut draw = Draw(seed);
    let language = *draw.pick(&LANGUAGES);
    let icons: Vec<Icon> = (0..4)
        .map(|_| Icon::new(draw.bytes(300)).unwrap())
        .collect();
    let definitions: Vec<Projected> = (0..3)
        .map(|at| definition(language, &format!("Amount {at}")))
        .collect();
    let facts = Facts {
        registered_at: DateTime::from_unix(1_700_000_000 + draw.below(1 << 30) as i64).unwrap(),
        language: Locale::parse(language).unwrap(),
        diagnostics: *draw.pick(&[Diagnostics::Shown, Diagnostics::Hidden]),
        systems: NymAuthSystem::ALL
            .into_iter()
            .filter(|_| draw.coin())
            .collect(),
        verifier_id: *draw.pick(&[VerifierIdForm::X509SanDns, VerifierIdForm::Semantic]),
        default_icon: draw.pick(&icons).clone(),
    };
    let credentials = (0..draw.below(60))
        .map(|at| credential(&mut draw, at as u64, &icons, &definitions))
        .collect();
    Projection { facts, credentials }
}

fn credential(
    draw: &mut Draw,
    at: u64,
    icons: &[Icon],
    definitions: &[Projected],
) -> RegisteredCredential<Projected, Icon> {
    let (format, name) = *draw.pick(&TYPES);
    let text = |draw: &mut Draw| CardText::new(draw.pick(&NAMES)).unwrap();
    let served = (0..draw.below(3))
        .map(|kind| {
            let type_id = TypeId::parse(&format!("urn:example:type:{kind}")).unwrap();
            let served = match draw.coin() {
                true => Ok(draw.pick(definitions).clone()),
                false => Err(*draw.pick(&UNSERVED)),
            };
            (type_id, served)
        })
        .collect();
    RegisteredCredential {
        entry: EntryRef::new(
            CredentialId::new(at + 1),
            BatchId::new(at + 1000),
            InstanceId::new(draw.next() % 4),
        ),
        credential_type: RegisteredType::new(format, name),
        key: *draw.pick(&[KeyHolding::Held, KeyHolding::NotHeld]),
        claims: claims(draw, format),
        card: RegisteredCard {
            title: text(draw),
            issuer: text(draw),
            icon: draw.pick(icons).clone(),
        },
        labels: ClaimLabels::new(labels(draw), labels(draw)),
        presentability: *draw.pick(&[Presentability::WithoutUi, Presentability::OnWalletUi]),
        issuer: IssuerFacts::new(
            (0..draw.below(3))
                .map(|_| KeyIdentifier::new(&draw.bytes(20)).unwrap())
                .collect(),
            (0..draw.below(3))
                .map(|_| {
                    let kind = *draw.pick(&[StoreType::EtsiTl, StoreType::OpenidFederation]);
                    StoreAuthority::new(kind, AuthorityValue::new(draw.pick(&NAMES)))
                })
                .collect(),
        ),
        transactions: ServedTypes::new(served, *draw.pick(&UNSERVED)).unwrap(),
    }
}

/// A definition of one claim, `name`d in `language`, projected from the configuration.
fn definition(language: &str, name: &str) -> Projected {
    let projection = json!({"language": language, "source": "configuration",
        "rulebook": "generic", "definition": {"claims": [{"path": ["amount"],
            "display": [{"locale": language, "name": name}]}]}});
    Projected::parse(&projection.to_string()).unwrap()
}

/// A claim tree of `format`: an SD-JWT VC's claims, or an mdoc's namespaces of elements.
fn claims(draw: &mut Draw, format: Format) -> ClaimTree {
    let root = match format {
        Format::SdJwtVc => members(draw, 2),
        Format::Mdoc => Cbor::Map(
            (0..=draw.below(2))
                .map(|at| (Cbor::text(&format!("org.example.{at}")), members(draw, 1)))
                .collect(),
        ),
    };
    let bytes = root.encode();
    ClaimTree::from_cbor(format, &cbor::decode(&bytes).unwrap()).unwrap()
}

/// A map of distinct names, each with a value nested at most `depth` deep.
fn members(draw: &mut Draw, depth: usize) -> Cbor {
    let mut names: Vec<&str> = NAMES.to_vec();
    Cbor::Map(
        (0..draw.below(5))
            .map(|_| {
                let name = names.remove(draw.below(names.len()));
                (Cbor::text(name), value(draw, depth))
            })
            .collect(),
    )
}

fn value(draw: &mut Draw, depth: usize) -> Cbor {
    match draw.below(if depth == 0 { 6 } else { 8 }) {
        0 => Cbor::text(draw.pick(&NAMES)),
        1 => Cbor::Unsigned(draw.next()),
        2 => Cbor::Negative(draw.next() >> 1),
        3 => Cbor::Bool(draw.coin()),
        4 => Cbor::Bytes(draw.bytes(16)),
        5 => Cbor::Tag(0, Box::new(Cbor::text("2024-02-29T12:00:00Z"))),
        6 => Cbor::Array(
            (0..draw.below(4))
                .map(|_| match draw.coin() {
                    true => value(draw, depth - 1),
                    false => Cbor::Encoded(vec![0xf7]),
                })
                .collect(),
        ),
        _ => members(draw, depth - 1),
    }
}

fn labels(draw: &mut Draw) -> Vec<DescribedLabel> {
    (0..draw.below(3))
        .map(|_| {
            let components = (0..=draw.below(3))
                .map(|_| match draw.below(3) {
                    0 => PathComponent::Key((*draw.pick(&NAMES)).to_owned()),
                    1 => PathComponent::Index(draw.next() % 8),
                    _ => PathComponent::Null,
                })
                .collect();
            let label = draw
                .coin()
                .then(|| LabelText::new(draw.pick(&NAMES)).unwrap());
            DescribedLabel::new(ClaimPath::new(components).unwrap(), label)
        })
        .collect()
}

#[test]
fn writing_then_reading_gives_the_projection_back() {
    for seed in 0..DRAWS {
        let written = projection(seed);
        let bytes = encode(&written).unwrap();
        assert_eq!(
            encode(&projection(seed)).unwrap(),
            bytes,
            "seed {seed}: equal projections give equal bytes"
        );
        let mut registration = Registration::open(Cursor::new(bytes.as_slice())).unwrap();
        assert_eq!(registration.projection().unwrap(), written, "seed {seed}");
        for (format, name) in TYPES {
            let credential_type = RegisteredType::new(format, name);
            let read: Vec<EntryRef> = registration
                .credentials(std::slice::from_ref(&credential_type))
                .unwrap()
                .iter()
                .map(RegisteredCredential::entry)
                .collect();
            let expected: Vec<EntryRef> = written
                .credentials
                .iter()
                .filter(|credential| credential.credential_type == credential_type)
                .map(RegisteredCredential::entry)
                .collect();
            assert_eq!(read, expected, "seed {seed}: the credentials of {name}");
        }
    }
}
