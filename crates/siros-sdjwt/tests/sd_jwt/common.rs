//! Crafted compact SD-JWTs.

use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_codec::base64url;

/// The disclosure of `array` and its SHA-256 digest.
pub fn disclosure(array: &Value) -> (String, String) {
    let encoded = base64url::encode(array.to_string().as_bytes()).into_string();
    let digest = base64url::encode(&Sha256::digest(encoded.as_bytes())).into_string();
    (encoded, digest)
}

/// A SHA-256 digest no disclosure has.
pub fn decoy(seed: &str) -> String {
    base64url::encode(&Sha256::digest(seed.as_bytes())).into_string()
}

/// The compact SD-JWT of the payload text `payload` and of `disclosures`. Its signature is a
/// placeholder.
pub fn compact(payload: &str, disclosures: &[&str]) -> String {
    let mut out = format!(
        "{}.{}.{}~",
        base64url::encode(br#"{"alg":"ES256","typ":"dc+sd-jwt"}"#).into_string(),
        base64url::encode(payload.as_bytes()).into_string(),
        base64url::encode(&[7; 64]).into_string(),
    );
    for d in disclosures {
        out.push_str(d);
        out.push('~');
    }
    out
}
