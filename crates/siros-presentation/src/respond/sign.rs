//! The `Sign` effects of a chosen offer, and the host's signatures parsed against them (A5).

use siros_codec::signature::Es256Signature;
use siros_credential::Credential;
use siros_mdoc::{es256_verifies, P256Key};
use siros_wallet_state::KeyId;

use crate::error::PresentationError;

siros_codec::position!(
    /// The identifier of a [`Sign`] effect, which its signature names: its position among the
    /// effects.
    pub SignId
);

/// The bytes a holder key signs for one presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SigningInput(Vec<u8>);

impl SigningInput {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// An ES256 signature the host makes (H3): of exactly [`Sign::input`], with the key pair
/// [`Sign::key`], returned as `r ‖ s`. It verifies under the credential's holder key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign {
    id: SignId,
    key: KeyId,
    input: SigningInput,
    holder: P256Key,
}

/// A signature that verifies under the holder key of its `Sign` effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedSignature(Es256Signature);

impl VerifiedSignature {
    /// The signature.
    pub(crate) fn signature(&self) -> &Es256Signature {
        &self.0
    }
}

/// Why the host's signatures do not answer the `Sign` effects (A5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum SignatureError {
    /// No signature answers this effect.
    Missing(SignId),
    /// The signature of this effect does not verify under its holder key.
    Invalid(SignId),
}

impl SignatureError {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Missing(_) => "signature_missing",
            Self::Invalid(_) => "signature_invalid",
        }
    }
}

impl Sign {
    /// The effect `id`: `credential`'s key pair signs `input`, and the signature verifies under
    /// its holder key, the SD-JWT VC's `cnf.jwk` or the mdoc's `deviceKey`.
    ///
    /// # Errors
    ///
    /// [`PresentationError::KeyIdMissing`] for a credential that names no key pair, and
    /// [`PresentationError::HolderKeyMissing`] for one bound to no key.
    pub(crate) fn new(
        id: SignId,
        credential: &Credential,
        input: SigningInput,
    ) -> Result<Self, PresentationError> {
        Ok(Self {
            id,
            key: key_id(credential)?,
            input,
            holder: credential
                .holder_key()
                .ok_or(PresentationError::HolderKeyMissing)?,
        })
    }

    /// The identifier the signature names.
    pub fn id(&self) -> SignId {
        self.id
    }

    /// The key pair that signs.
    pub fn key(&self) -> &KeyId {
        &self.key
    }

    /// The bytes it signs.
    pub fn input(&self) -> &[u8] {
        &self.input.0
    }

    /// The signature `signature`, `r ‖ s`, when it verifies under the holder key (A5).
    ///
    /// # Panics
    ///
    /// When `signature` is not 64 bytes.
    #[expect(
        clippy::panic,
        reason = "the host returns ES256 signatures as `r ‖ s` (H3); another length is a bug of \
                  the host, and no presentation can carry it"
    )]
    fn verified(&self, signature: Vec<u8>) -> Result<VerifiedSignature, SignatureError> {
        let signature = match Es256Signature::parse(&signature) {
            Ok(signature) => signature,
            Err(length) => panic!(
                "the host's signature of effect {} has {} bytes; r || s has 64",
                self.id.value(),
                length.0
            ),
        };
        if es256_verifies(&self.holder, &self.input.0, &signature) {
            Ok(VerifiedSignature(signature))
        } else {
            Err(SignatureError::Invalid(self.id))
        }
    }
}

/// The key pair `credential`'s entry names.
///
/// # Errors
///
/// [`PresentationError::KeyIdMissing`] for an entry without one.
pub(crate) fn key_id(credential: &Credential) -> Result<KeyId, PresentationError> {
    credential
        .key_id()
        .cloned()
        .ok_or(PresentationError::KeyIdMissing)
}

/// The signature of each effect of `signs`, by its identifier, verified under the key the
/// effect names (A5).
///
/// # Errors
///
/// [`SignatureError`]: a signature that does not verify, or an effect without one.
///
/// # Panics
///
/// When a signature names no effect, two answer one effect, or one is not 64 bytes.
#[expect(
    clippy::panic,
    reason = "the host answers each `Sign` effect once, by its identifier (A5); an answer to no \
              effect or a second answer is a bug of the host, and either signature could be \
              the one presented"
)]
pub(crate) fn verified(
    signs: &[Sign],
    signatures: Vec<(SignId, Vec<u8>)>,
) -> Result<Vec<VerifiedSignature>, SignatureError> {
    let mut by_id: Vec<Option<VerifiedSignature>> = vec![None; signs.len()];
    for (id, signature) in signatures {
        let Some((slot, sign)) = by_id.get_mut(id.value()).zip(signs.get(id.value())) else {
            panic!(
                "the host signed effect {}, which no Sign effect has",
                id.value()
            );
        };
        if slot.is_some() {
            panic!("the host answered Sign effect {} twice", id.value());
        }
        *slot = Some(sign.verified(signature)?);
    }
    by_id
        .into_iter()
        .zip(signs)
        .map(|(signature, sign)| signature.ok_or(SignatureError::Missing(sign.id)))
        .collect()
}
