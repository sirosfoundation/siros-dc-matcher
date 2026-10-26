//! ES256 verification (RFC 9053, Section 2.1).

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

use crate::mso::P256Key;

/// Whether `signature` (`r ‖ s`) is an ES256 signature of `message` under `key`.
pub fn es256_verifies(key: &P256Key, message: &[u8], signature: &[u8; 64]) -> bool {
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_sec1_bytes(&key.sec1()),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}
