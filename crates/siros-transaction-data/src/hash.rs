//! The transaction data profile of OpenID4VP 1.0, B.3.3.1: the request member
//! `transaction_data_hashes_alg` and the KB-JWT claims `transaction_data_hashes` and
//! `transaction_data_hashes_alg`.

use sha2::{Digest, Sha256, Sha384, Sha512};
use siros_codec::base64url;

use crate::error::TransactionDataError;
use crate::json::{self, Json};

/// A hash algorithm of the IANA Named Information Hash Algorithm Registry that this wallet
/// computes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlg {
    /// `sha-256`, which every implementation supports (B.3.3.1).
    Sha256,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
}

impl HashAlg {
    /// The Hash Name String of the registry.
    #[must_use]
    pub fn identifier(self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        }
    }

    /// The element of `transaction_data_hashes` for `entry`, the string the request carried:
    /// base64url of the hash over its bytes. The string is hashed as received, without
    /// base64url decoding (B.3.3.1).
    #[must_use]
    pub fn hash(self, entry: &str) -> String {
        let bytes = entry.as_bytes();
        match self {
            Self::Sha256 => base64url::encode(&Sha256::digest(bytes)).into(),
            Self::Sha384 => base64url::encode(&Sha384::digest(bytes)).into(),
            Self::Sha512 => base64url::encode(&Sha512::digest(bytes)).into(),
        }
    }

    /// The algorithm the Hash Name String `name` names.
    fn named(name: &str) -> Option<Self> {
        [Self::Sha256, Self::Sha384, Self::Sha512]
            .into_iter()
            .find(|alg| alg.identifier() == name)
    }
}

/// The algorithms an entry accepts for its hash.
pub(crate) enum Accepted {
    /// The entry carries no `transaction_data_hashes_alg`: `sha-256` only.
    Default,
    /// The algorithms of `transaction_data_hashes_alg` this wallet computes, in the verifier's
    /// order; at least one.
    Listed(Vec<HashAlg>),
}

/// The name of the request member.
pub(crate) const HASHES_ALG: &str = "transaction_data_hashes_alg";

impl Accepted {
    /// The algorithms `value`, the entry's `transaction_data_hashes_alg`, accepts: a
    /// non-empty array of Hash Name Strings. A name this wallet does not compute is passed
    /// over.
    pub(crate) fn parse(value: Option<Json>) -> Result<Self, TransactionDataError> {
        let Some(value) = value else {
            return Ok(Self::Default);
        };
        let names = json::array(value, HASHES_ALG)?;
        if names.is_empty() {
            return Err(TransactionDataError::InvalidValue(HASHES_ALG));
        }
        let mut algs = Vec::new();
        for name in names {
            if let Some(alg) = HashAlg::named(&json::text(name, HASHES_ALG)?) {
                algs.push(alg);
            }
        }
        if algs.is_empty() {
            return Err(TransactionDataError::HashAlgUnsupported);
        }
        Ok(Self::Listed(algs))
    }

    /// The algorithms, in the verifier's order.
    fn algs(&self) -> &[HashAlg] {
        match self {
            Self::Default => &[HashAlg::Sha256],
            Self::Listed(algs) => algs,
        }
    }

    /// Whether the request carried `transaction_data_hashes_alg`, which the KB-JWT then
    /// repeats.
    fn carried(&self) -> bool {
        matches!(self, Self::Listed(_))
    }
}

/// The algorithm of one KB-JWT, shared by the entries bound to its credential (B.3.3.1).
#[derive(Clone, Copy)]
pub(crate) struct Choice {
    alg: HashAlg,
    carried: bool,
}

impl Choice {
    /// The first algorithm of the first entry that every entry accepts.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::HashAlgConflict`]: no algorithm is common to all.
    pub(crate) fn of(accepted: &[&Accepted]) -> Result<Self, TransactionDataError> {
        let first = accepted.first().map_or(&[][..], |a| a.algs());
        let alg = first
            .iter()
            .copied()
            .find(|alg| accepted.iter().all(|a| a.algs().contains(alg)))
            .ok_or(TransactionDataError::HashAlgConflict)?;
        Ok(Self {
            alg,
            carried: accepted.iter().any(|a| a.carried()),
        })
    }

    /// The algorithm.
    pub(crate) fn alg(self) -> HashAlg {
        self.alg
    }

    /// Whether the KB-JWT carries `transaction_data_hashes_alg`: when any entry bound to the
    /// credential carried it (B.3.3.1).
    pub(crate) fn carried(self) -> bool {
        self.carried
    }
}
