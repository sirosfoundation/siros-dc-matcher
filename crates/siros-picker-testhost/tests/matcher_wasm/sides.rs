//! What each side offers for a case: the wallet's plan over the request intake verified, and
//! the picker's entry sets over the registration the wallet writes, in one form to compare.

use android_credman::{Picked, Shown as HostShown};
use serde_json::Value;
use siros_codec::date::DateTime;
use siros_display::Field;
use siros_oid4vp::Verdict;
use siros_presentation::testing::host::label_text;
use siros_presentation::testing::verifier::{dc_api_intake, intake_with, NOW, ORIGIN};
use siros_presentation::testing::wallet::Wallet;
use siros_presentation::{
    ConsentView, CredentialView, Fulfilment, HostDisplay, OfferView, Pick, Planned, WalletDisplay,
};
use siros_registration::{write, CredentialIcon, Diagnostics, RasterIcon, RegistrationInput};
use siros_transaction_data::{LocationStep, RowValue, Segment};

use siros_picker_testhost::{run, Captured, CapturedEntry, Invocation};

use crate::matcher_wasm;

/// The host levels the picker runs at: the first with entry sets, and the one that shows every
/// option, delegation included.
pub const LEVELS: [u32; 2] = [2, 7];

/// The first host level with the delegation call (K4).
const DELEGATION: u32 = 7;

/// The first host level with a payment entry's `additional_info`.
const ADDITIONAL_INFO: u32 = 3;

/// The payment rulebooks' types: EC TS12 v1.0.1's and PaSO's.
const PAYMENTS: [&str; 2] = ["urn:eudi:sca:payment:1", "urn:paso:sca:global:payment:1"];

/// An offer as either side shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    /// Each member: its Credential Query, and each credential it presents.
    pub members: Vec<(String, Vec<Presented>)>,
    /// Whether the wallet presents the offer without its UI: the picker's `Full` delegation,
    /// the wallet's `WalletDisplay::NotNeeded`; `None` below the level with the delegation
    /// call.
    pub background: Option<bool>,
    /// The purpose line.
    pub purpose: Option<String>,
}

/// A credential of an offer as either side shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presented {
    /// `credentialId`.
    pub credential: u64,
    /// The card's title.
    pub title: String,
    /// The card's issuer line; `None` for an entry without a subtitle.
    pub issuer: Option<String>,
    /// The fields: each claim row or proof statement, and each displayed claim of the
    /// transaction a verification entry shows.
    pub fields: Vec<(String, Option<String>)>,
    /// The payee, the amount and the further lines of a payment entry.
    pub payment: Option<(String, String, Vec<String>)>,
}

/// The request intake verifies of the DC API request `request`, the host trusting every
/// verifier; `None` when intake refuses it.
pub fn intake(request: &[u8]) -> Option<siros_oid4vp::VerifiedRequest> {
    intake_with(dc_api_intake(request), Verdict::Trusted).ok()
}

/// The offers of the wallet's plan, as its consent view shows them to a host at `level`;
/// `entries` are the request's `transaction_data` entries, decoded.
pub fn wallet_offers(view: &ConsentView<'_>, entries: &[Value], level: u32) -> Vec<Offered> {
    view.offers()
        .iter()
        .map(|offer| wallet_offer(offer, entries, level))
        .collect()
}

fn wallet_offer(offer: &OfferView, entries: &[Value], level: u32) -> Offered {
    Offered {
        members: offer
            .members()
            .iter()
            .map(|member| {
                let credentials = member
                    .credentials()
                    .iter()
                    .map(|credential| wallet_presented(credential, entries, level))
                    .collect();
                (member.query_id().as_str().to_owned(), credentials)
            })
            .collect(),
        background: (level >= DELEGATION)
            .then(|| offer.wallet_display() == WalletDisplay::NotNeeded),
        purpose: offer.purpose().map(host_text),
    }
}

/// `text` as a host string carries it: each NUL a space.
fn host_text(text: &str) -> String {
    text.replace('\0', " ")
}

/// A credential of the wallet's view: its claim or proof statement rows as the picker formats a
/// row, and the transaction bound to it as a payment entry or as rows, for a host at `level`.
/// An entry with ad-hoc metadata the picker defers to the wallet (K2), and shows no transaction
/// for.
fn wallet_presented(credential: &CredentialView, entries: &[Value], level: u32) -> Presented {
    let mut fields: Vec<(String, Option<String>)> = credential.fields().iter().map(texts).collect();
    let mut payment = None;
    let bound = credential
        .transaction()
        .filter(|bound| entries[bound.entry().value()].get("metadata").is_none());
    if let Some(bound) = bound {
        let entry = &entries[bound.entry().value()];
        let view = bound.view();
        let rows = view.rows().iter().map(|row| {
            let paid = paid_location(row.location().steps());
            (paid, label_text(row.label()), value_text(row.value()))
        });
        match expected_payment(entry) {
            Some((payee, amount)) => {
                let lines =
                    view.transaction_title()
                        .map(label_text)
                        .into_iter()
                        .chain(rows.filter(|(paid, ..)| !paid).map(
                            |(_, label, value)| match value {
                                Some(value) => format!("{label}: {value}"),
                                None => label,
                            },
                        ))
                        .filter(|_| level >= ADDITIONAL_INFO)
                        .collect();
                payment = Some((payee, amount, lines));
            }
            None => fields.extend(rows.map(|(_, label, value)| (label, value))),
        }
    }
    Presented {
        credential: credential.entry().credential_id().value(),
        title: credential.card().title().as_str().to_owned(),
        issuer: Some(credential.card().issuer().as_str().to_owned()),
        fields,
        payment,
    }
}

/// The payee and the amount a payment entry shows for `entry`, when its type is a payment
/// rulebook's: `payee.name`, and the amount with its currency.
fn expected_payment(entry: &Value) -> Option<(String, String)> {
    if !PAYMENTS.contains(&entry["type"].as_str()?) {
        return None;
    }
    let payload = &entry["payload"];
    let payee = payload["payee"]["name"].as_str()?.to_owned();
    let amount = match (&payload["amount"], payload["currency"].as_str()) {
        (Value::Number(amount), Some(currency)) => format!("{amount} {currency}"),
        (Value::String(amount), _) => amount.clone(),
        _ => return None,
    };
    Some((payee, amount))
}

/// Whether `steps` locate the payee's name, the amount or the currency.
fn paid_location(steps: &[LocationStep]) -> bool {
    let keys: Vec<&str> = steps
        .iter()
        .filter_map(|step| match step {
            LocationStep::Key(key) => Some(key.as_str()),
            LocationStep::Index(_) => None,
        })
        .collect();
    keys.len() == steps.len()
        && [&["payee", "name"][..], &["amount"], &["currency"]].contains(&keys.as_slice())
}

/// A row's value as the payload writes it; `None` for a label alone, empty for an image.
fn value_text(value: &RowValue) -> Option<String> {
    match value {
        RowValue::LabelOnly => None,
        RowValue::Value(scalar) => Some(scalar.text()),
        RowValue::Template(interpolated) => Some(
            interpolated
                .segments()
                .iter()
                .map(|segment| match segment {
                    Segment::Text(text) => text.clone(),
                    Segment::Value(value) => value.text(),
                })
                .collect(),
        ),
        RowValue::Image(_) => Some(String::new()),
    }
}

/// A picker field's texts.
fn texts(field: &Field) -> (String, Option<String>) {
    (
        field.name().as_str().to_owned(),
        field.value().map(|value| value.as_str().to_owned()),
    )
}

/// The registration the wallet writes for the picker, at the time of the plan.
pub fn registration(wallet: &Wallet, icons: &[CredentialIcon]) -> Vec<u8> {
    write(&input(wallet, icons, &icon(64, 64))).unwrap()
}

/// What the wallet writes its registration from, at the time of the plan: its state, the
/// icons the host prepared, and `default_icon`.
pub fn input<'a>(
    wallet: &'a Wallet,
    icons: &'a [CredentialIcon],
    default_icon: &'a RasterIcon,
) -> RegistrationInput<'a> {
    RegistrationInput {
        credentials: &wallet.credentials,
        records: wallet.records(),
        display: &wallet.display,
        language: &wallet.language,
        card_wording: &wallet.card_wording,
        held: &wallet.metadata,
        configuration: &wallet.configuration,
        trust: &wallet.trust,
        systems: &wallet.systems,
        verifier_id: wallet.verifier_id,
        background: &wallet.background,
        icons,
        default_icon,
        diagnostics: Diagnostics::Hidden,
        now: DateTime::from_unix(NOW).unwrap(),
    }
}

/// A PNG of `width` by `height` pixels, as far as its header reads: the signature and the IHDR
/// chunk of an 8-bit truecolour image.
pub fn png(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    bytes.extend(width.to_be_bytes());
    bytes.extend(height.to_be_bytes());
    bytes.extend([8, 2, 0, 0, 0]);
    bytes
}

/// The icon of [`png`] `width` by `height`.
pub fn icon(width: u32, height: u32) -> RasterIcon {
    RasterIcon::parse(png(width, height)).unwrap()
}

/// What the picker emits for `request` over `registration` for a host at `level`.
pub fn picker_run(request: &[u8], registration: Vec<u8>, level: u32) -> Captured {
    run(
        matcher_wasm(),
        Invocation {
            request: request.to_vec(),
            credentials: registration,
            calling_package: "com.android.chrome".into(),
            origin: ORIGIN.into(),
            wasm_version: level,
        },
    )
    .unwrap()
}

/// The pick an entry carries (K3).
pub fn pick(entry: &CapturedEntry) -> Pick {
    let picked = Picked::parse(entry.metadata.as_deref().unwrap()).unwrap();
    Pick::parse(picked.data().unwrap()).unwrap()
}

/// The offers of the picker's entry sets for a host at `level`, in the order of their offers:
/// each set's entries grouped by the Credential Query their pick names.
pub fn picker_offers(captured: &Captured, level: u32) -> Vec<Offered> {
    let mut offers: Vec<(usize, Offered)> = Vec::new();
    for entry in &captured.entries {
        let pick = pick(entry);
        let at = pick.offer().value();
        assert_eq!(entry.set_id, format!("siros-{at}"), "an offer's set");
        let query = pick.query().as_str().to_owned();
        let presented = Presented {
            credential: pick.credential().value(),
            title: entry.title.clone(),
            issuer: entry.subtitle.clone(),
            fields: entry.fields.clone(),
            payment: entry.payment.as_ref().map(|payment| {
                let lines = payment
                    .additional_info
                    .iter()
                    .flat_map(|info| info.lines())
                    .map(str::to_owned)
                    .collect();
                (payment.merchant.clone(), payment.amount.clone(), lines)
            }),
        };
        let background = (level >= DELEGATION).then_some(entry.delegation == Some(1));
        if !offers.iter().any(|(offer, _)| *offer == at) {
            offers.push((
                at,
                Offered {
                    members: Vec::new(),
                    background,
                    purpose: entry.disclaimer.clone(),
                },
            ));
        }
        let (_, offer) = offers.iter_mut().find(|(offer, _)| *offer == at).unwrap();
        assert_eq!(offer.background, background, "one delegation per set");
        match offer.members.iter_mut().find(|(q, _)| *q == query) {
            Some((_, credentials)) => credentials.push(presented),
            None => offer.members.push((query, vec![presented])),
        }
    }
    offers.sort_by_key(|(at, _)| *at);
    offers.into_iter().map(|(_, offer)| offer).collect()
}

/// The offer of `planned` the picks of the entries of the picker's offer at `offer` select,
/// when the wallet then chooses it (K3): from its background service when the picker delegated
/// the offer, with what the host showed of the picked entries (K4), else on its UI.
pub fn chosen_through_picks(
    planned: &Planned<'_>,
    captured: &Captured,
    offer: usize,
) -> Option<usize> {
    let entries: Vec<&CapturedEntry> = captured
        .entries
        .iter()
        .filter(|entry| entry.set_id == format!("siros-{offer}"))
        .collect();
    let picks: Vec<Pick> = entries.iter().map(|entry| pick(entry)).collect();
    let selection = planned.picked(&picks).ok()?;
    let fulfilment = if entries.iter().all(|entry| entry.delegation == Some(1)) {
        Fulfilment::Background(HostDisplay::of(entries.iter().map(|entry| {
            match Picked::parse(entry.metadata.as_deref().unwrap())
                .unwrap()
                .shown()
            {
                HostShown::Full => HostDisplay::Full,
                HostShown::Skipped => HostDisplay::Skipped,
            }
        })))
    } else {
        Fulfilment::WalletUi
    };
    planned
        .choose(&selection, fulfilment)
        .ok()
        .map(|_| selection.offer().value())
}
