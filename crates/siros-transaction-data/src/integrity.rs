//! Integrity metadata (W3C Subresource Integrity, Section 3), as SD-JWT VC pins a metadata
//! document with a `#integrity` claim (SD-JWT VC, Section 7).

use sha2::{Digest, Sha256, Sha384, Sha512};
use siros_codec::base64;

use crate::error::TransactionDataError;

/// A hash algorithm of SRI, weakest first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Alg {
    Sha256,
    Sha384,
    Sha512,
}

impl Alg {
    /// The algorithm of the SRI token `token`, compared without regard to ASCII case.
    fn named(token: &str) -> Option<Self> {
        [
            ("sha256", Self::Sha256),
            ("sha384", Self::Sha384),
            ("sha512", Self::Sha512),
        ]
        .into_iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(token))
        .map(|(_, alg)| alg)
    }

    /// The length of a digest, in bytes.
    fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }
}

/// The digests of the strongest algorithm an integrity metadata string names (SRI, Section
/// 3.3.4): at least one.
pub(crate) struct Integrity {
    alg: Alg,
    digests: Vec<Vec<u8>>,
}

impl Integrity {
    /// The integrity metadata `text`: whitespace-separated `alg-base64` expressions, each with
    /// optional `?` options (SRI, Section 3.1).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::IntegrityMalformed`]: no expression of SHA-256, SHA-384 or
    /// SHA-512, or one of them whose value is not the base64 of a digest of its algorithm.
    pub(crate) fn parse(text: &str) -> Result<Self, TransactionDataError> {
        let mut expressions = Vec::new();
        for token in text.split_ascii_whitespace() {
            let expression = token.split('?').next().unwrap_or(token);
            let Some((name, value)) = expression.split_once('-') else {
                continue;
            };
            let Some(alg) = Alg::named(name) else {
                continue;
            };
            let digest = base64::decode(value)
                .filter(|d| d.len() == alg.len())
                .ok_or(TransactionDataError::IntegrityMalformed)?;
            expressions.push((alg, digest));
        }
        let alg = expressions
            .iter()
            .map(|(alg, _)| *alg)
            .max()
            .ok_or(TransactionDataError::IntegrityMalformed)?;
        Ok(Self {
            alg,
            digests: expressions
                .into_iter()
                .filter(|(a, _)| *a == alg)
                .map(|(_, digest)| digest)
                .collect(),
        })
    }

    /// Refuses `document` unless its digest is one the metadata lists (SRI, Section 3.3.5).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::IntegrityMismatch`].
    pub(crate) fn check(&self, document: &[u8]) -> Result<(), TransactionDataError> {
        let digest = self.alg.digest(document);
        if self.digests.contains(&digest) {
            Ok(())
        } else {
            Err(TransactionDataError::IntegrityMismatch)
        }
    }
}
