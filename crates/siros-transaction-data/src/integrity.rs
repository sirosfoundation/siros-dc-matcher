//! Integrity metadata (W3C Subresource Integrity, Section 3), as SD-JWT VC pins a metadata
//! document with a `#integrity` claim (SD-JWT VC, Section 7).

use siros_codec::base64;

use crate::error::TransactionDataError;
use crate::hash::HashAlg;

/// The digests of the strongest algorithm an integrity metadata string names (SRI, Section
/// 3.3.4): at least one.
pub(crate) struct Integrity {
    alg: HashAlg,
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
        let expressions = text
            .split_ascii_whitespace()
            .filter_map(expression)
            .map(|(alg, value)| {
                base64::decode(value)
                    .ok()
                    .filter(|digest| digest.len() == alg.len())
                    .map(|digest| (alg, digest))
                    .ok_or(TransactionDataError::IntegrityMalformed)
            })
            .collect::<Result<Vec<_>, _>>()?;
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
        if self.digests.contains(&self.alg.digest(document)) {
            Ok(())
        } else {
            Err(TransactionDataError::IntegrityMismatch)
        }
    }
}

/// The algorithm and the base64 value of the SRI token `token`, its options aside; `None` for
/// a token of an algorithm this wallet does not compute.
fn expression(token: &str) -> Option<(HashAlg, &str)> {
    let expression = token.split('?').next().unwrap_or(token);
    let (name, value) = expression.split_once('-')?;
    Some((HashAlg::sri_named(name)?, value))
}
