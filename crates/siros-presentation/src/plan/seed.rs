//! The `secret_seed` an issuer delivered with a nym_auth credential: the `opening` of its
//! `hash_commitment` Auxiliary Data Entry for `ssc` (privatedata 3.1, Section 5A; Credential
//! Auxiliary Data, Section 4.1; nym_auth rulebook, "Issuance of the seeds").

use serde_json::Value;
use siros_codec::base64url;
use siros_credential::Credential;
use siros_zkp_req_nym_auth::catalogue::MDOC_DOCTYPE;
use zeroize::Zeroizing;

/// The claim the seed commits to.
const SSC: [&str; 2] = [MDOC_DOCTYPE, "ssc"];

/// Why a credential gives no seed. A credential without one answers no nym_auth query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NoSeed {
    /// No `hash_commitment` entry names `ssc`.
    Missing,
    /// Several do (Credential Auxiliary Data, Section 3).
    Repeated,
    /// An `auxiliary_data` value is no array of entries, or the entry for `ssc` breaks the
    /// rules of `hash_commitment`: an `alg` other than `sha-256`, an `encoding`, or an
    /// `opening` that is not 16 bytes of unpadded base64url.
    Malformed,
}

/// The 16-byte `secret_seed` delivered with `credential`. It is zeroed on drop.
pub(crate) fn delivered(credential: &Credential) -> Result<Zeroizing<[u8; 16]>, NoSeed> {
    let mut found = None;
    for value in credential.auxiliary_data() {
        let entries: Vec<Value> =
            serde_json::from_str(value.json()).map_err(|_| NoSeed::Malformed)?;
        for entry in entries {
            let names_ssc = entry.get("type").and_then(Value::as_str) == Some("hash_commitment")
                && entry
                    .get("path")
                    .and_then(Value::as_array)
                    .is_some_and(|path| path.iter().map(Value::as_str).eq(SSC.map(Some)));
            if !names_ssc {
                continue;
            }
            if found.replace(entry).is_some() {
                return Err(NoSeed::Repeated);
            }
        }
    }
    let entry = found.ok_or(NoSeed::Missing)?;
    let opening = match (
        entry.get("alg").and_then(Value::as_str),
        entry.get("encoding"),
        entry.get("opening").and_then(Value::as_str),
    ) {
        (Some("sha-256"), None, Some(opening)) => opening,
        _ => return Err(NoSeed::Malformed),
    };
    let decoded = Zeroizing::new(base64url::decode(opening).ok_or(NoSeed::Malformed)?);
    let mut seed = Zeroizing::new([0u8; 16]);
    if decoded.len() != seed.len() {
        return Err(NoSeed::Malformed);
    }
    seed.copy_from_slice(&decoded);
    Ok(seed)
}
