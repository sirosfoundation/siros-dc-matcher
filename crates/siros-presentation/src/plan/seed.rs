//! The `secret_seed` an issuer delivered with a nym_auth credential: the `opening` of its
//! `hash_commitment` Auxiliary Data Entry for `ssc` (privatedata 3.1, Section 5A; Credential
//! Auxiliary Data, Section 4.1; nym_auth rulebook, "Issuance of the seeds").

use itertools::Itertools;
use serde_json::error::Category;
use serde_json::Value;
use siros_codec::base64url;
use siros_credential::Credential;
use siros_zkp_req_nym_auth::attestation::SecretSeed;
use siros_zkp_req_nym_auth::catalogue::MDOC_DOCTYPE;
use zeroize::Zeroizing;

/// The claim the seed commits to.
const SSC: [&str; 2] = [MDOC_DOCTYPE, "ssc"];

/// Why a credential gives no `secret_seed`. A credential without one answers no nym_auth query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum NoSeed {
    /// An `auxiliary_data` value is no JSON array of entries.
    Entries(JsonCause),
    /// No `hash_commitment` entry names `ssc`.
    Missing,
    /// Several do (Credential Auxiliary Data, Section 3).
    Repeated,
    /// The entry's `alg` is not `sha-256`.
    Algorithm,
    /// The entry has an `encoding`, which a seed's `hash_commitment` leaves out.
    Encoding,
    /// The entry's `opening` is not 16 bytes of unpadded base64url.
    Opening,
}

impl NoSeed {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Entries(_) => "seed_entries",
            Self::Missing => "seed_missing",
            Self::Repeated => "seed_repeated",
            Self::Algorithm => "seed_algorithm",
            Self::Encoding => "seed_encoding",
            Self::Opening => "seed_opening",
        }
    }
}

/// Why a JSON text does not read: serde_json's category of the error, and where it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonCause {
    category: Category,
    line: usize,
    column: usize,
}

impl JsonCause {
    fn of(error: &serde_json::Error) -> Self {
        Self {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        }
    }

    /// The kind of the error: syntax, data of another shape, or an early end.
    pub fn category(&self) -> Category {
        self.category
    }

    /// The line of the error, from 1.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The column of the error, from 1.
    pub fn column(&self) -> usize {
        self.column
    }
}

/// The `secret_seed` delivered with `credential`: the opening of its one `hash_commitment`
/// entry for `ssc`.
pub(crate) fn delivered(credential: &Credential) -> Result<SecretSeed, NoSeed> {
    let entries: Vec<Value> = credential
        .auxiliary_data()
        .iter()
        .map(|value| {
            serde_json::from_str::<Vec<Value>>(value.json())
                .map_err(|error| NoSeed::Entries(JsonCause::of(&error)))
        })
        .flatten_ok()
        .try_collect()?;
    let entry = entries
        .iter()
        .filter(|entry| commits_to_ssc(entry))
        .at_most_one()
        .map_err(|_| NoSeed::Repeated)?
        .ok_or(NoSeed::Missing)?;
    opening(entry)
}

/// Whether `entry` is a `hash_commitment` of the claim `ssc`.
fn commits_to_ssc(entry: &Value) -> bool {
    entry.get("type").and_then(Value::as_str) == Some("hash_commitment")
        && entry
            .get("path")
            .and_then(Value::as_array)
            .is_some_and(|path| path.iter().map(Value::as_str).eq(SSC.map(Some)))
}

/// The seed `entry` opens with: `sha-256`, no `encoding`, and a 16-byte `opening`.
fn opening(entry: &Value) -> Result<SecretSeed, NoSeed> {
    if entry.get("alg").and_then(Value::as_str) != Some("sha-256") {
        return Err(NoSeed::Algorithm);
    }
    if entry.get("encoding").is_some() {
        return Err(NoSeed::Encoding);
    }
    let decoded = entry
        .get("opening")
        .and_then(Value::as_str)
        .and_then(|text| base64url::decode(text).ok())
        .map(Zeroizing::new)
        .ok_or(NoSeed::Opening)?;
    let mut seed = Zeroizing::new([0u8; 16]);
    if decoded.len() != seed.len() {
        return Err(NoSeed::Opening);
    }
    // The lengths are equal, checked above, so the copy cannot panic.
    seed.copy_from_slice(&decoded);
    Ok(SecretSeed::new(seed))
}
