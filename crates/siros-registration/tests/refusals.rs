//! The reader refuses a registration that breaks a rule of `docs/registration.md`, one row per
//! rule, each with its cause. The rows change a registration the writer wrote, at the offsets
//! the layout gives.

use std::io::Cursor;

use serde_json::json;
use siros_codec::cbor::{self, Value as Cbor};
use siros_codec::date::DateTime;
use siros_credential::Format;
use siros_presentation::testing::host::holding_absent;
use siros_presentation::testing::verifier::NOW;
use siros_presentation::testing::wallet::{card_wording, mdoc, sd_jwt, Held, Wallet, MDL, MDL_NS};
use siros_registration::{
    write, CredentialFault, Diagnostics, FactsFault, IndexFault, Member, OutOfBounds, RasterIcon,
    RegisteredType, Registration, RegistrationError, RegistrationInput, SectionKind, TableFault,
    TileFault, TypeName, Unlisted, Within,
};
use siros_transaction_data::Configuration;

const PID: &str = "https://credentials.example/pid";
const LOYALTY: &str = "https://shop.example/loyalty";
/// A transaction data type the configuration defines for the PIDs.
const POINTS: &str = "urn:example:loyalty-points:1";

/// A PNG of 64 by 64 pixels, as far as its header reads.
fn icon() -> RasterIcon {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend(64u32.to_be_bytes());
    png.extend(64u32.to_be_bytes());
    png.extend([8, 2, 0, 0, 0]);
    RasterIcon::parse(png).unwrap()
}

/// The registration of a wallet of three types: two PIDs and a loyalty card, SD-JWT VCs, which
/// the index lists first, and an mDL. The configuration defines a transaction data type for the
/// PIDs: the definitions table holds its definition.
fn registration() -> Vec<u8> {
    let name = [("given_name", json!("Erika"))];
    let mut wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", sd_jwt(PID, &name)),
        Held::new(2, "dc+sd-jwt", sd_jwt(LOYALTY, &name)),
        Held::new(
            3,
            "mso_mdoc",
            mdoc(MDL, MDL_NS, &[("age_over_18", Cbor::Bool(true))]),
        ),
        Held::new(4, "dc+sd-jwt", sd_jwt(PID, &name)),
    ]);
    let points = json!([{"type": POINTS, "vct_values": [PID], "definition": {"claims": [
        {"path": ["points"], "display": [{"locale": "en", "name": "Points"}]}]}}]);
    wallet.configuration = Configuration::parse(&points.to_string()).unwrap();
    wallet.metadata = holding_absent(&[PID, LOYALTY]);
    write(&RegistrationInput {
        credentials: &wallet.credentials,
        records: wallet.records(),
        display: &wallet.display,
        language: &wallet.language,
        card_wording: &card_wording(),
        held: &wallet.metadata,
        configuration: &wallet.configuration,
        trust: &wallet.trust,
        systems: &wallet.systems,
        verifier_id: wallet.verifier_id,
        background: &wallet.background,
        icons: &[],
        default_icon: &icon(),
        diagnostics: Diagnostics::Hidden,
        now: DateTime::from_unix(NOW).unwrap(),
    })
    .unwrap()
}

/// The little-endian number at `at`.
fn number(blob: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(blob[at..at + 4].try_into().unwrap())
}

/// The offset and length of the `kind`th section (1 to 6) the directory lists.
fn section(blob: &[u8], kind: usize) -> (usize, usize) {
    let entry = 12 + 12 * (kind - 1);
    (
        number(blob, entry + 4) as usize,
        number(blob, entry + 8) as usize,
    )
}

/// An index entry: its format code, and its type's name and records.
#[derive(Clone)]
struct Entry {
    format: u32,
    name: Vec<u8>,
    records: Vec<u8>,
}

/// The sections of a registration, in the directory's order.
struct Layout([Vec<u8>; 6]);

impl Layout {
    fn of(blob: &[u8]) -> Self {
        Self(std::array::from_fn(|at| {
            let (offset, length) = section(blob, at + 1);
            blob[offset..offset + length].to_vec()
        }))
    }

    /// The header, the directory, then the sections, each where the one before it ends.
    fn blob(&self) -> Vec<u8> {
        let mut blob = b"\x89SRG\r\n\x1a\n".to_vec();
        blob.extend(1u32.to_le_bytes());
        let mut at = 84;
        for (kind, section) in (1u32..).zip(&self.0) {
            for word in [kind, at, section.len() as u32] {
                blob.extend(word.to_le_bytes());
            }
            at += section.len() as u32;
        }
        blob.extend(self.0.concat());
        blob
    }

    fn entries(&self) -> Vec<Entry> {
        let [_, index, names, records, ..] = &self.0;
        index
            .chunks(20)
            .map(|entry| {
                let word = |at: usize| number(entry, 4 * at) as usize;
                Entry {
                    format: word(0) as u32,
                    name: names[word(1)..word(1) + word(2)].to_vec(),
                    records: records[word(3)..word(3) + word(4)].to_vec(),
                }
            })
            .collect()
    }

    /// The layout with the index, names and records of `entries`, in their order, each name and
    /// each run of records where the one before it ends.
    fn with_entries(mut self, entries: &[Entry]) -> Self {
        let [_, index, names, records, ..] = &mut self.0;
        index.clear();
        names.clear();
        records.clear();
        for entry in entries {
            for word in [
                entry.format,
                names.len() as u32,
                entry.name.len() as u32,
                records.len() as u32,
                entry.records.len() as u32,
            ] {
                index.extend(word.to_le_bytes());
            }
            names.extend(&entry.name);
            records.extend(&entry.records);
        }
        self
    }

    /// The layout with `change` added to word `word` (0 to 4) of the index entry at `entry`.
    fn shifted(self, entry: usize, word: usize, change: i64) -> Self {
        self.shifted_word(1, 5 * entry + word, change)
    }

    /// The layout with `change` added to the word at `word` of the section at `section` (0
    /// to 5).
    fn shifted_word(mut self, section: usize, word: usize, change: i64) -> Self {
        let at = 4 * word;
        let value = i64::from(number(&self.0[section], at)) + change;
        self.0[section][at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
        self
    }
}

/// Where `needle` first starts in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap()
}

/// The refusal of `blob`: when it opens, of reading the credentials of `types`.
fn refusal(blob: &[u8], types: &[RegisteredType]) -> RegistrationError {
    let read = Registration::open(Cursor::new(blob), |mut registration| {
        registration.credentials(types).map(drop)
    })
    .and_then(|read| read);
    read.expect_err("the reader refuses the registration")
}

#[test]
fn each_rule_refuses_with_its_cause() {
    let honest = registration();
    let pid = RegisteredType::new(Format::SdJwtVc, TypeName::new(PID).unwrap());
    let mdl = RegisteredType::new(Format::Mdoc, TypeName::new(MDL).unwrap());
    assert_eq!(
        Registration::open(Cursor::new(&honest), |mut registration| {
            registration.credentials(&[pid.clone(), mdl]).unwrap().len()
        })
        .unwrap(),
        3,
        "the honest registration reads"
    );
    let changed = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut blob = honest.clone();
        change(&mut blob);
        blob
    };

    let bad_magic = changed(&|blob| blob[1] = b'X');
    assert!(matches!(refusal(&bad_magic, &[]), RegistrationError::Magic));

    let unknown_version = changed(&|blob| blob[8..12].copy_from_slice(&2u32.to_le_bytes()));
    assert!(matches!(
        refusal(&unknown_version, &[]),
        RegistrationError::Version(2)
    ));

    // The icons section, the last one, one byte longer than the blob holds.
    let (icons_at, icons) = section(&honest, 6);
    let past_the_blob = changed(&|blob| {
        blob[80..84].copy_from_slice(&(icons as u32 + 1).to_le_bytes());
    });
    let error = refusal(&past_the_blob, &[]);
    assert!(
        matches!(
            error,
            RegistrationError::OutOfBlob(OutOfBounds { within: Within::Blob, offset, length, limit })
                if offset.value() == icons_at as u64
                    && length.value() == icons as u64 + 1
                    && limit.value() == honest.len() as u64
        ),
        "{error:?}"
    );

    // The index sorts PID, then the loyalty card, then the mDL.
    let entries = Layout::of(&honest).entries();
    let [pid_entry, loyalty, mdl_entry] = [&entries[0], &entries[1], &entries[2]];
    let index_refusal = |layout: Layout| match refusal(&layout.blob(), &[]) {
        RegistrationError::Index(at, fault) => (at.value(), fault),
        error => panic!("{error:?}"),
    };

    // The loyalty card's entry names PID.
    let repeated = Entry {
        name: pid_entry.name.clone(),
        ..loyalty.clone()
    };
    let layout =
        Layout::of(&honest).with_entries(&[pid_entry.clone(), repeated, mdl_entry.clone()]);
    assert_eq!(index_refusal(layout), (1, IndexFault::Repeated));

    let layout =
        Layout::of(&honest).with_entries(&[loyalty.clone(), pid_entry.clone(), mdl_entry.clone()]);
    assert_eq!(index_refusal(layout), (1, IndexFault::Order));

    // The loyalty card's name starts a byte after PID's ends, and ends where it did.
    let pid_name = pid_entry.name.len() as u64;
    let layout = Layout::of(&honest).shifted(1, 1, 1).shifted(1, 2, -1);
    let fault = index_refusal(layout);
    assert!(
        matches!(fault, (1, IndexFault::Name(TileFault::Gap { end, offset }))
            if end.value() == pid_name && offset.value() == pid_name + 1),
        "{fault:?}"
    );

    // The loyalty card's records start a byte before PID's end, and end where they did.
    let pid_records = pid_entry.records.len() as u64;
    let layout = Layout::of(&honest).shifted(1, 3, -1).shifted(1, 4, 1);
    let fault = index_refusal(layout);
    assert!(
        matches!(fault, (1, IndexFault::Records(TileFault::Overlap { end, offset }))
            if end.value() == pid_records && offset.value() == pid_records - 1),
        "{fault:?}"
    );

    // The default icon, the icons table's one entry, starts a byte after the table ends.
    let layout = Layout::of(&honest)
        .shifted_word(5, 1, 1)
        .shifted_word(5, 2, -1);
    let error = refusal(&layout.blob(), &[]);
    assert!(
        matches!(error, RegistrationError::Table(SectionKind::Icons,
            TableFault::Entry(at, TileFault::Gap { end, offset }))
            if at.value() == 0 && end.value() == 12 && offset.value() == 13),
        "{error:?}"
    );

    // The definitions table counts 2^28 entries.
    let mut layout = Layout::of(&honest);
    let definitions = layout.0[4].len() as u64;
    layout.0[4][..4].copy_from_slice(&(1u32 << 28).to_le_bytes());
    let error = refusal(&layout.blob(), &[]);
    assert!(
        matches!(error, RegistrationError::Table(SectionKind::Definitions,
            TableFault::Past(OutOfBounds { within: Within::Section(SectionKind::Definitions),
                offset, length, limit }))
            if offset.value() == 4 && length.value() == 1 << 31 && limit.value() == definitions),
        "{error:?}"
    );

    // The facts name the wallet's icon 1 of the one-entry icons table.
    let mut layout = Layout::of(&honest);
    let at = find(&layout.0[0], b"\x6cdefault_icon\x00") + 13;
    layout.0[0][at] = 0x01;
    let error = refusal(&layout.blob(), &[]);
    assert!(
        matches!(
            error,
            RegistrationError::Facts(FactsFault::DefaultIcon(Unlisted {
                index: 1,
                entries: 1
            }))
        ),
        "{error:?}"
    );

    // PID's first record names definition 1 of the one-entry definitions table.
    let mut layout = Layout::of(&honest);
    let served = [&[0x78, POINTS.len() as u8][..], POINTS.as_bytes(), &[0x00]].concat();
    let at = find(&layout.0[3], &served) + served.len() - 1;
    layout.0[3][at] = 0x01;
    let error = refusal(&layout.blob(), std::slice::from_ref(&pid));
    assert!(
        matches!(
            error,
            RegistrationError::Credential {
                fault: CredentialFault::Unlisted(
                    Member::ServedTypes,
                    Unlisted {
                        index: 1,
                        entries: 1
                    }
                ),
                ..
            }
        ),
        "{error:?}"
    );

    // The PID's record with its member `position` renamed.
    let unparsed = changed(&|blob| {
        let (records, length) = section(blob, 4);
        let section = &mut blob[records..records + length];
        let at = section
            .windows(9)
            .position(|window| window == b"\x68position")
            .unwrap();
        section[at + 2] = b'X';
    });
    let error = refusal(&unparsed, std::slice::from_ref(&pid));
    assert!(
        matches!(
            &error,
            RegistrationError::Credential { fault: CredentialFault::MemberUnknown(name), .. }
                if name == "pXsition"
        ),
        "{error:?}"
    );

    // The two PIDs' records swapped: the PID is the index's first entry.
    let swapped = changed(&|blob| {
        let (index, _) = section(blob, 2);
        let (records, _) = section(blob, 4);
        let at = records + number(blob, index + 12) as usize;
        let end = at + number(blob, index + 16) as usize;
        let items = cbor::decode_sequence(&blob[at..end]).unwrap();
        let [first, second] = items.as_slice() else {
            panic!("two PID records: {items:?}");
        };
        let reordered = [second.raw(), first.raw()].concat();
        blob[at..end].copy_from_slice(&reordered);
    });
    let error = refusal(&swapped, &[pid]);
    assert!(
        matches!(&error, RegistrationError::RecordOrder { record, .. } if record.value() == 1),
        "{error:?}"
    );
}
