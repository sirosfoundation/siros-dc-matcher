//! Writes the registration of a sample wallet to the file its argument names: one mDL holding
//! `age_over_18` and `family_name`, labelled in English, with the picker's diagnostics shown.
//! `scripts/run_matcher.mjs` runs `matcher.wasm` over it.
//!
//!     cargo run -p siros-registration --features wallet --example sample_registration -- out.cbor

use std::process::ExitCode;

use serde_json::json;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_display::{DisplayCache, IssuerMetadata};
use siros_presentation::testing::verifier::NOW;
use siros_presentation::testing::wallet::{mdoc, Held, Wallet, MDL, MDL_NS};
use siros_registration::{write, Diagnostics, RegistrationInput};

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
    write(&RegistrationInput {
        credentials: &wallet.credentials,
        records: wallet.records(),
        display: &wallet.display,
        language: &wallet.language,
        held: &wallet.metadata,
        configuration: &wallet.configuration,
        trust: &wallet.trust,
        systems: &wallet.systems,
        background: &wallet.background,
        icons: &[],
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
