//! The reader refuses a registration that breaks a rule of `docs/registration.md`, one row per
//! rule, each with its cause. The rows change a registration the writer wrote, at the offsets
//! the layout gives.

use std::io::Cursor;

use serde_json::json;
use siros_codec::cbor::{self, Value as Cbor};
use siros_codec::date::DateTime;
use siros_credential::Format;
use siros_presentation::testing::verifier::NOW;
use siros_presentation::testing::wallet::{card_wording, mdoc, sd_jwt, Held, Wallet, MDL, MDL_NS};
use siros_registration::{
    write, CredentialFault, Diagnostics, IndexFault, OutOfBounds, RasterIcon, RegisteredType,
    Registration, RegistrationError, RegistrationInput, TypeName, Within,
};

const PID: &str = "https://credentials.example/pid";
const LOYALTY: &str = "https://shop.example/loyalty";

/// A PNG of 64 by 64 pixels, as far as its header reads.
fn icon() -> RasterIcon {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    png.extend(64u32.to_be_bytes());
    png.extend(64u32.to_be_bytes());
    png.extend([8, 2, 0, 0, 0]);
    RasterIcon::parse(png).unwrap()
}

/// The registration of a wallet of three types: two PIDs and a loyalty card, SD-JWT VCs, which
/// the index lists first, and an mDL.
fn registration() -> Vec<u8> {
    let name = [("given_name", json!("Erika"))];
    let wallet = Wallet::new(vec![
        Held::new(1, "dc+sd-jwt", sd_jwt(PID, &name)),
        Held::new(2, "dc+sd-jwt", sd_jwt(LOYALTY, &name)),
        Held::new(
            3,
            "mso_mdoc",
            mdoc(MDL, MDL_NS, &[("age_over_18", Cbor::Bool(true))]),
        ),
        Held::new(4, "dc+sd-jwt", sd_jwt(PID, &name)),
    ]);
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

/// The refusal of `blob`: when it opens, of reading the credentials of `types`.
fn refusal(blob: &[u8], types: &[RegisteredType]) -> RegistrationError {
    let read = Registration::open(Cursor::new(blob))
        .and_then(|mut registration| registration.credentials(types).map(drop));
    read.expect_err("the reader refuses the registration")
}

#[test]
fn each_rule_refuses_with_its_cause() {
    let honest = registration();
    let pid = RegisteredType::new(Format::SdJwtVc, TypeName::new(PID).unwrap());
    let mdl = RegisteredType::new(Format::Mdoc, TypeName::new(MDL).unwrap());
    assert_eq!(
        Registration::open(Cursor::new(&honest))
            .unwrap()
            .credentials(&[pid.clone(), mdl])
            .unwrap()
            .len(),
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

    // The first and the last of the three index entries swapped: a search for the type now
    // last reads the middle entry, then the first, which sorts above the middle one.
    let out_of_order = changed(&|blob| {
        let (index, _) = section(blob, 2);
        let first: Vec<u8> = blob[index..index + 20].to_vec();
        let last: Vec<u8> = blob[index + 40..index + 60].to_vec();
        blob[index..index + 20].copy_from_slice(&last);
        blob[index + 40..index + 60].copy_from_slice(&first);
    });
    let error = refusal(&out_of_order, std::slice::from_ref(&pid));
    assert!(
        matches!(error, RegistrationError::Index(at, IndexFault::Order) if at.value() == 0),
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
