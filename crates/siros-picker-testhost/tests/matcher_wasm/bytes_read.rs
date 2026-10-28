//! The picker reads of the registration only what a request needs (`docs/registration.md`):
//! the header, the directory, the index, the types' names, the tables of the definitions and the
//! icons, and the facts; the records of the type the request asks for; the definitions the
//! request's entry names for them; and the icons of the entries it emits. The count of bytes the host copies is the sum of those parts, which
//! the layout's lengths and the writer's projection give.

use serde_json::{json, Value};
use siros_codec::cbor::Value as Cbor;
use siros_presentation::testing::wallet::{mdoc, sd_jwt, Held, MDL, MDL_NS};
use siros_registration::{encode, project, CredentialIcon, RegisteredCredential};
use siros_transaction_data::{Projected, TypeId};
use siros_wallet_state::CredentialId;

use crate::paso::{
    configured_wallet, payment_definition, points_definition, request, ACCOUNT, CARD, LOYALTY,
    PAYMENT, PID, PID_2, POINTS,
};
use crate::sides::{icon, input, picker_run};

/// The header and the directory: 12 and 72 bytes.
const HEADER_AND_DIRECTORY: usize = 84;

/// An index entry.
const INDEX_ENTRY: usize = 20;

/// The count of a table's entries.
const TABLE_COUNT: usize = 4;

/// A table entry.
const TABLE_ENTRY: usize = 8;

/// PaSO Core, Annex A.1: a query for a card, and a payment entry that targets it.
const A1_REQUEST: &str =
    include_str!("../../../siros-transaction-data/tests/vectors/paso/core-a1-request.json");
const A1_ENTRY: &str =
    include_str!("../../../siros-transaction-data/tests/vectors/paso/core-a1-entry.json");

/// The little-endian number at `at`.
fn number(blob: &[u8], at: usize) -> usize {
    u32::from_le_bytes(blob[at..at + 4].try_into().unwrap()) as usize
}

/// The offset and length of the `kind`th section (1 to 6) the directory lists.
fn section(blob: &[u8], kind: usize) -> (usize, usize) {
    let entry = 12 + 12 * (kind - 1);
    (number(blob, entry + 4), number(blob, entry + 8))
}

/// The length of the records the index lists for the SD-JWT VCs of `vct`.
fn records_of(blob: &[u8], vct: &str) -> usize {
    let (index, length) = section(blob, 2);
    let (names, _) = section(blob, 3);
    (index..index + length)
        .step_by(INDEX_ENTRY)
        .find(|&entry| {
            let name = names + number(blob, entry + 4);
            number(blob, entry) == 1
                && &blob[name..name + number(blob, entry + 8)] == vct.as_bytes()
        })
        .map(|entry| number(blob, entry + 16))
        .unwrap()
}

/// Each value of `values` once, in order.
fn distinct<T: PartialEq>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut seen = Vec::new();
    for value in values {
        if !seen.contains(&value) {
            seen.push(value);
        }
    }
    seen
}

/// 210 credentials: SD-JWT VCs of five types and mdocs of two, 30 of each, every seventh a card.
fn held() -> Vec<Held> {
    let name = [("given_name", json!("Erika"))];
    let card = [("pan_last_four", json!("4242")), ("scheme", json!("visa"))];
    let age = [("age_over_18", Cbor::Bool(true))];
    (1..=210)
        .map(|id| match id % 7 {
            0 => Held::new(id, "dc+sd-jwt", sd_jwt(CARD, &card)),
            1 => Held::new(id, "dc+sd-jwt", sd_jwt(ACCOUNT, &[])),
            2 => Held::new(id, "dc+sd-jwt", sd_jwt(PID, &name)),
            3 => Held::new(id, "dc+sd-jwt", sd_jwt(PID_2, &name)),
            4 => Held::new(id, "dc+sd-jwt", sd_jwt(LOYALTY, &[])),
            5 => Held::new(id, "mso_mdoc", mdoc(MDL, MDL_NS, &age)),
            _ => {
                let pid = "eu.europa.ec.eudi.pid.1";
                Held::new(id, "mso_mdoc", mdoc(pid, pid, &age))
            }
        })
        .collect()
}

#[test]
fn the_picker_reads_what_the_request_needs() {
    let configured = json!([
        {"type": PAYMENT, "vct_values": [CARD, ACCOUNT], "definition": payment_definition()},
        {"type": POINTS, "vct_values": [PID], "definition": points_definition()}
    ]);
    let wallet = configured_wallet(held(), &configured, &[CARD, ACCOUNT, PID, PID_2, LOYALTY]);
    // An icon the host prepared for each card, three in turn, and one for credential 1, an
    // account the request asks for no entry of. No entry shows the wallet's icon.
    let mut icons: Vec<CredentialIcon> = (0..30u32)
        .map(|card| CredentialIcon {
            credential: CredentialId::new(u64::from(7 * card + 7)),
            icon: icon(100 + card % 3 * 20, 80),
        })
        .collect();
    icons.push(CredentialIcon {
        credential: CredentialId::new(1),
        icon: icon(200, 80),
    });
    let default_icon = icon(64, 64);
    let projection = project(&input(&wallet, &icons, &default_icon)).unwrap();
    let blob = encode(&projection).unwrap();
    let a1_request: Value = serde_json::from_str(A1_REQUEST).unwrap();
    let a1_entry: Value = serde_json::from_str(A1_ENTRY).unwrap();
    let request = request(a1_request["dcql_query"].clone(), &[a1_entry]);

    // An entry and a name per type.
    let index_and_names: usize = distinct(
        projection
            .credentials()
            .iter()
            .map(|credential| credential.credential_type()),
    )
    .iter()
    .map(|credential_type| INDEX_ENTRY + credential_type.as_str().len())
    .sum();
    // The tables number each distinct icon and definition once.
    let icon_entries = distinct(
        std::iter::once(projection.facts().default_icon()).chain(
            projection
                .credentials()
                .iter()
                .map(|credential| credential.card().icon()),
        ),
    )
    .len();
    let definition_entries = distinct(projection.credentials().iter().flat_map(|credential| {
        credential
            .transactions()
            .types()
            .iter()
            .filter_map(|(_, served)| served.as_ref().ok().map(Projected::to_json))
    }))
    .len();
    let tables = 2 * TABLE_COUNT + TABLE_ENTRY * (icon_entries + definition_entries);
    let cards: Vec<&RegisteredCredential<Projected, _>> = projection
        .credentials()
        .iter()
        .filter(|credential| credential.credential_type().as_str() == CARD)
        .collect();
    let payment = TypeId::parse(PAYMENT).unwrap();
    let definitions: usize = distinct(
        cards
            .iter()
            .map(|card| card.transactions().serve(&payment).unwrap().to_json()),
    )
    .iter()
    .map(String::len)
    .sum();
    let icons_emitted: usize = distinct(cards.iter().map(|card| card.card().icon().as_bytes()))
        .iter()
        .map(|icon| icon.len())
        .sum();
    let (_, facts) = section(&blob, 1);
    let expected = HEADER_AND_DIRECTORY
        + facts
        + index_and_names
        + tables
        + records_of(&blob, CARD)
        + definitions
        + icons_emitted;

    let captured = picker_run(&request, blob.clone(), 7);
    let emitted: Vec<&str> = captured
        .entries
        .iter()
        .map(|entry| entry.credential_id.as_str())
        .collect();
    let card_ids: Vec<String> = cards
        .iter()
        .map(|card| card.entry().credential_id().to_string())
        .collect();
    assert_eq!(emitted, card_ids, "the picker emits an entry for each card");
    assert_eq!(cards.len(), 30);
    assert_eq!(projection.credentials().len(), 210);
    assert_eq!(
        captured.credential_bytes,
        expected,
        "of a registration of {} bytes",
        blob.len()
    );
}
