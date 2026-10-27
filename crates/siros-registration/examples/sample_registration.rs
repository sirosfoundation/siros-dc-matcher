//! Writes the registration of a sample wallet to the file its argument names: one mDL holding
//! `age_over_18` and `family_name`, labelled in English, with the picker's diagnostics shown.
//! `scripts/run_matcher.mjs` runs `matcher.wasm` over it.
//!
//!     cargo run -p siros-registration --features wallet --example sample_registration -- out.cbor

use std::process::ExitCode;

use serde_json::json;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_display::{CardText, CardWording, DisplayCache, IssuerMetadata, IssuerTemplate};
use siros_presentation::testing::verifier::NOW;
use siros_presentation::testing::wallet::{mdoc, Held, Wallet, MDL, MDL_NS};
use siros_registration::{write, Diagnostics, RasterIcon, RegistrationInput};

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: sample_registration <file>");
        return ExitCode::from(2);
    };
    match registration().and_then(|bytes| std::fs::write(&path, bytes).map_err(|e| e.to_string())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sample_registration: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The registration of the sample wallet, at the fixtures' time.
fn registration() -> Result<Vec<u8>, String> {
    let items = [
        ("age_over_18", Cbor::Bool(true)),
        ("family_name", Cbor::text("Johansson")),
    ];
    let mut wallet = Wallet::new(vec![Held::new(1, "mso_mdoc", mdoc(MDL, MDL_NS, &items))]);
    wallet.display = display()?;
    let now = DateTime::from_unix(NOW).ok_or("the fixtures' time is no date")?;
    let card_wording = CardWording {
        title: CardText::new("Credential").map_err(|e| e.to_string())?,
        issuer: CardText::new("Unknown issuer").map_err(|e| e.to_string())?,
        issuer_template: Some(
            IssuerTemplate::parse("Issued by {issuer}").map_err(|e| e.to_string())?,
        ),
    };
    let default_icon = RasterIcon::parse(ICON_PNG.to_vec()).map_err(|e| e.to_string())?;
    write(&RegistrationInput {
        credentials: &wallet.credentials,
        records: wallet.records(),
        display: &wallet.display,
        language: &wallet.language,
        card_wording: &card_wording,
        held: &wallet.metadata,
        configuration: &wallet.configuration,
        trust: &wallet.trust,
        systems: &wallet.systems,
        verifier_id: wallet.verifier_id,
        background: &wallet.background,
        icons: &[],
        default_icon: &default_icon,
        diagnostics: Diagnostics::Shown,
        now,
    })
    .map_err(|e| e.to_string())
}

/// The issuer metadata of the sample mDL: its card and claim labels in English.
fn display() -> Result<DisplayCache, String> {
    let issuer = json!({
        "credential_issuer": "https://issuer.example",
        "credential_endpoint": "https://issuer.example/credential",
        "display": [{"name": "Transportstyrelsen", "locale": "en"}],
        "credential_configurations_supported": {"example": {
            "format": "mso_mdoc", "doctype": MDL,
            "credential_metadata": {
                "display": [{"name": "Driving Licence", "locale": "en"}],
                "claims": [
                    {"path": [MDL_NS, "age_over_18"], "display": [{"name": "Over 18", "locale": "en"}]},
                    {"path": [MDL_NS, "family_name"], "display": [{"name": "Family name", "locale": "en"}]}
                ]}}}
    });
    let metadata = IssuerMetadata::merge(&issuer, "example", None).map_err(|e| e.to_string())?;
    DisplayCache::new(vec![metadata], Vec::new()).map_err(|e| e.to_string())
}

/// The wallet's default icon: a 64x64 solid-colour PNG.
#[rustfmt::skip]
const ICON_PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x40, 0x08, 0x02, 0x00, 0x00, 0x00, 0x25, 0x0B, 0xE6,
    0x89, 0x00, 0x00, 0x00, 0x50, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0xED, 0xCF, 0x41, 0x09, 0x00,
    0x00, 0x08, 0x04, 0xB0, 0xCB, 0x61, 0x10, 0xDB, 0xD8, 0xBF, 0x86, 0x11, 0x7C, 0x0B, 0x83, 0x15,
    0x58, 0xAA, 0xE7, 0xB5, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x5C, 0x16, 0x49, 0xAB, 0xD0, 0x97, 0x3A, 0x79, 0x4A, 0x21, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];
