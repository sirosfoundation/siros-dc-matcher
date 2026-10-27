//! What the JWE and the `COSE_Encrypt` envelopes share: the ECDH-ES agreement with the
//! Verifier's key, the content encryption key, and AES GCM.

use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::aes::Aes192;
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
use p256::ecdh::{EphemeralSecret, SharedSecret};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::CryptoRngCore;

use super::{EncryptionFault, ResponseError};
use crate::verified::{ContentEncryption, Encryption};

/// An ephemeral key's agreement with the Verifier's key (RFC 7518, Section 4.6; RFC 9053,
/// Section 6.3).
pub(super) struct Agreement {
    /// The ephemeral public key's coordinates.
    pub(super) x: [u8; 32],
    pub(super) y: [u8; 32],
    /// The agreement, whose x-coordinate is Z.
    pub(super) shared: SharedSecret,
}

/// A fresh ephemeral key from `rng`, agreed with the chosen key.
///
/// # Panics
///
/// When the ephemeral public key has no affine coordinates.
#[expect(
    clippy::panic,
    reason = "a p256 PublicKey is never the identity, so its uncompressed point has both \
              coordinates; a point without them is a bug of the library, and no agreement \
              can be sent from it"
)]
pub(super) fn agree(encryption: &Encryption, rng: &mut impl CryptoRngCore) -> Agreement {
    let ephemeral = EphemeralSecret::random(rng);
    let shared = ephemeral.diffie_hellman(&encryption.key);
    let point = ephemeral.public_key().to_encoded_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        panic!("the ephemeral public key has no affine coordinates");
    };
    Agreement {
        x: (*x).into(),
        y: (*y).into(),
        shared,
    }
}

/// A content encryption key: as many bytes as its `enc` takes.
#[derive(Clone, PartialEq, Eq)]
pub struct ContentKey(Vec<u8>);

impl ContentKey {
    /// The key derived for `enc` from the KDF output `derived`.
    ///
    /// # Panics
    ///
    /// When `derived` is shorter than `enc`'s key.
    #[expect(
        clippy::expect_used,
        reason = "both KDFs give at least the key of every `enc`: the 32 bytes of SHA-256, or \
                  HKDF's output of the key's length; a shorter one is a bug of the core"
    )]
    pub(super) fn of(enc: ContentEncryption, derived: &[u8]) -> Self {
        derived
            .get(..enc.key_len())
            .map(|key| Self(key.to_vec()))
            .expect("the KDF output holds the content key")
    }

    /// The key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A fresh 96-bit IV from `rng`.
pub(super) fn iv(rng: &mut impl CryptoRngCore) -> [u8; 12] {
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);
    iv
}

/// What AES GCM gives: the ciphertext and the 128-bit tag.
pub(super) struct Sealed {
    pub(super) ciphertext: Vec<u8>,
    pub(super) tag: Vec<u8>,
}

/// `plaintext` sealed under `key` with `iv` and `aad`.
///
/// # Panics
///
/// When `key` is not of `enc`'s length.
///
/// # Errors
///
/// [`EncryptionFault::Seal`] when AES GCM refuses `plaintext` or `aad` as too long.
#[expect(
    clippy::expect_used,
    reason = "the callers derive `key` for `enc`, so it has `enc`'s length; another length is \
              a bug of the core, and no ciphertext can be sent"
)]
pub(super) fn seal(
    enc: ContentEncryption,
    key: &ContentKey,
    iv: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Sealed, ResponseError> {
    let nonce = Nonce::from(iv);
    let mut ciphertext = plaintext.to_vec();
    let key = key.as_bytes();
    let length = "a content key has the length of its enc";
    let tag = match enc {
        ContentEncryption::A128Gcm => Aes128Gcm::new_from_slice(key)
            .expect(length)
            .encrypt_in_place_detached(&nonce, aad, &mut ciphertext),
        ContentEncryption::A192Gcm => AesGcm::<Aes192, U12>::new_from_slice(key)
            .expect(length)
            .encrypt_in_place_detached(&nonce, aad, &mut ciphertext),
        ContentEncryption::A256Gcm => Aes256Gcm::new_from_slice(key)
            .expect(length)
            .encrypt_in_place_detached(&nonce, aad, &mut ciphertext),
    }
    .map_err(|_| ResponseError::EncryptionFailed(EncryptionFault::Seal))?;
    Ok(Sealed {
        ciphertext,
        tag: tag.to_vec(),
    })
}
