//! The writer's round trip: writing a projection, then reading it back, whole and by type,
//! gives the projection again, and equal projections give equal bytes. The projections are
//! drawn at random from fixed seeds.

#![allow(clippy::arithmetic_side_effects)]

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
    TypeName,
};
use crate::wire::UNSERVED;

/// The projections drawn.
const DRAWS: u64 = 64;

/// What a draw built no value of: the part named.
#[derive(Debug, thiserror::Error)]
#[error("the draw built no {0}")]
struct Unbuilt(&'static str);

/// A drawn part that may not build.
trait Built<T> {
    /// The part, or [`Unbuilt`] naming `part`.
    fn built(self, part: &'static str) -> Result<T, Unbuilt>;
}

impl<T, E> Built<T> for Result<T, E> {
    fn built(self, part: &'static str) -> Result<T, Unbuilt> {
        self.map_err(|_| Unbuilt(part))
    }
}

impl<T> Built<T> for Option<T> {
    fn built(self, part: &'static str) -> Result<T, Unbuilt> {
        self.ok_or(Unbuilt(part))
    }
}

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

    /// A number below `n`, which is at least 1.
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> Result<&'a T, Unbuilt> {
        let at = self.next().checked_rem(items.len() as u64).built("pick")?;
        items.get(at as usize).built("pick")
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

fn projection(seed: u64) -> Result<Projection, Unbuilt> {
    let mut draw = Draw(seed);
    let language = *draw.pick(&LANGUAGES)?;
    let icons: Vec<Icon> = (0..4)
        .map(|_| Icon::new(draw.bytes(300)).built("icon"))
        .collect::<Result<_, _>>()?;
    let definitions: Vec<Projected> = (0..3)
        .map(|at| definition(language, &format!("Amount {at}")))
        .collect::<Result<_, _>>()?;
    let registered_at = 1_700_000_000 + draw.below(1 << 30) as i64;
    let facts = Facts {
        registered_at: DateTime::from_unix(registered_at).built("time")?,
        language: Locale::parse(language).built("language")?,
        diagnostics: *draw.pick(&[Diagnostics::Shown, Diagnostics::Hidden])?,
        systems: NymAuthSystem::ALL
            .into_iter()
            .filter(|_| draw.coin())
            .collect(),
        verifier_id: *draw.pick(&[VerifierIdForm::X509SanDns, VerifierIdForm::Semantic])?,
        default_icon: draw.pick(&icons)?.clone(),
    };
    let credentials = (0..draw.below(60))
        .map(|at| credential(&mut draw, at as u64, &icons, &definitions))
        .collect::<Result<_, _>>()?;
    Ok(Projection { facts, credentials })
}

fn credential(
    draw: &mut Draw,
    at: u64,
    icons: &[Icon],
    definitions: &[Projected],
) -> Result<RegisteredCredential<Projected, Icon>, Unbuilt> {
    let (format, name) = *draw.pick(&TYPES)?;
    let text = |draw: &mut Draw| CardText::new(draw.pick(&NAMES)?).built("card text");
    let served = (0..draw.below(3))
        .map(|kind| {
            let type_id = TypeId::parse(&format!("urn:example:type:{kind}")).built("type")?;
            let served = match draw.coin() {
                true => Ok(draw.pick(definitions)?.clone()),
                false => Err(*draw.pick(&UNSERVED)?),
            };
            Ok((type_id, served))
        })
        .collect::<Result<_, Unbuilt>>()?;
    Ok(RegisteredCredential {
        entry: EntryRef::new(
            CredentialId::new(at + 1),
            BatchId::new(at + 1000),
            InstanceId::new(draw.next() % 4),
        ),
        credential_type: RegisteredType::new(format, TypeName::new(name).built("type name")?),
        key: *draw.pick(&[KeyHolding::Held, KeyHolding::NotHeld])?,
        claims: claims(draw, format)?,
        card: RegisteredCard {
            title: text(draw)?,
            issuer: text(draw)?,
            icon: draw.pick(icons)?.clone(),
        },
        labels: ClaimLabels::new(labels(draw)?, labels(draw)?),
        presentability: *draw.pick(&[Presentability::WithoutUi, Presentability::OnWalletUi])?,
        issuer: facts(draw)?,
        transactions: ServedTypes::new(served, *draw.pick(&UNSERVED)?).built("served types")?,
    })
}

/// Issuer facts: up to two key identifiers and up to two admitting authorities.
fn facts(draw: &mut Draw) -> Result<IssuerFacts, Unbuilt> {
    let keys = (0..draw.below(3))
        .map(|_| KeyIdentifier::new(&draw.bytes(20)).built("key identifier"))
        .collect::<Result<_, _>>()?;
    let admitting = (0..draw.below(3))
        .map(|_| {
            let kind = *draw.pick(&[StoreType::EtsiTl, StoreType::OpenidFederation])?;
            let value = AuthorityValue::new(draw.pick(&NAMES)?);
            Ok(StoreAuthority::new(kind, value))
        })
        .collect::<Result<_, Unbuilt>>()?;
    Ok(IssuerFacts::new(keys, admitting))
}

/// A definition of one claim, `name`d in `language`, projected from the configuration.
fn definition(language: &str, name: &str) -> Result<Projected, Unbuilt> {
    let projection = json!({"language": language, "source": "configuration",
        "rulebook": "generic", "definition": {"claims": [{"path": ["amount"],
            "display": [{"locale": language, "name": name}]}]}});
    Projected::parse(&projection.to_string()).built("definition")
}

/// A claim tree of `format`: an SD-JWT VC's claims, or an mdoc's namespaces of elements.
fn claims(draw: &mut Draw, format: Format) -> Result<ClaimTree, Unbuilt> {
    let root = match format {
        Format::SdJwtVc => members(draw, 2)?,
        Format::Mdoc => Cbor::Map(
            (0..=draw.below(2))
                .map(|at| Ok((Cbor::text(&format!("org.example.{at}")), members(draw, 1)?)))
                .collect::<Result<_, Unbuilt>>()?,
        ),
    };
    let bytes = root.encode();
    let item = cbor::decode(&bytes).built("claims")?;
    ClaimTree::from_cbor(format, &item).built("claim tree")
}

/// A map of up to four distinct names, each with a value nested at most `depth` deep.
fn members(draw: &mut Draw, depth: usize) -> Result<Cbor, Unbuilt> {
    let names: Vec<&str> = NAMES.into_iter().filter(|_| draw.coin()).take(4).collect();
    names
        .into_iter()
        .map(|name| Ok((Cbor::text(name), value(draw, depth)?)))
        .collect::<Result<_, Unbuilt>>()
        .map(Cbor::Map)
}

fn value(draw: &mut Draw, depth: usize) -> Result<Cbor, Unbuilt> {
    Ok(match draw.below(if depth == 0 { 6 } else { 8 }) {
        0 => Cbor::text(draw.pick(&NAMES)?),
        1 => Cbor::Unsigned(draw.next()),
        2 => Cbor::Negative(draw.next() >> 1),
        3 => Cbor::Bool(draw.coin()),
        4 => Cbor::Bytes(draw.bytes(16)),
        5 => Cbor::Tag(0, Box::new(Cbor::text("2024-02-29T12:00:00Z"))),
        6 => Cbor::Array(
            (0..draw.below(4))
                .map(|_| match draw.coin() {
                    true => value(draw, depth - 1),
                    false => Ok(Cbor::Encoded(vec![0xf7])),
                })
                .collect::<Result<_, _>>()?,
        ),
        _ => members(draw, depth - 1)?,
    })
}

fn labels(draw: &mut Draw) -> Result<Vec<DescribedLabel>, Unbuilt> {
    (0..draw.below(3))
        .map(|_| {
            let components = (0..=draw.below(3))
                .map(|_| {
                    Ok(match draw.below(3) {
                        0 => PathComponent::Key((*draw.pick(&NAMES)?).to_owned()),
                        1 => PathComponent::Index(draw.next() % 8),
                        _ => PathComponent::Null,
                    })
                })
                .collect::<Result<_, Unbuilt>>()?;
            let label = match draw.coin() {
                true => Some(LabelText::new(draw.pick(&NAMES)?).built("label")?),
                false => None,
            };
            let path = ClaimPath::new(components).built("path")?;
            Ok(DescribedLabel::new(path, label))
        })
        .collect()
}

#[test]
fn writing_then_reading_gives_the_projection_back() -> Result<(), Box<dyn std::error::Error>> {
    for seed in 0..DRAWS {
        let written = projection(seed)?;
        let bytes = encode(&written)?;
        assert_eq!(
            encode(&projection(seed)?)?,
            bytes,
            "seed {seed}: equal projections give equal bytes"
        );
        let mut registration = Registration::open(Cursor::new(bytes.as_slice()))?;
        assert_eq!(registration.projection()?, written, "seed {seed}");
        for (format, name) in TYPES {
            let credential_type = RegisteredType::new(format, TypeName::new(name)?);
            let read: Vec<EntryRef> = registration
                .credentials(std::slice::from_ref(&credential_type))?
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
    Ok(())
}
