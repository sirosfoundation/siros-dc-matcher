//! The transaction data profile of OpenID4VP 1.0, B.3.3.1: the request member
//! `transaction_data_hashes_alg` and the KB-JWT claims `transaction_data_hashes` and
//! `transaction_data_hashes_alg`.

use sha2::{Digest, Sha256, Sha384, Sha512};
use siros_codec::base64url::{self, Base64Url};
use siros_codec::json::Json;
use siros_oid4vp::TransactionDataItem;

use crate::error::{MemberPath, TransactionDataError};
use crate::json;

/// A hash algorithm of the IANA Named Information Hash Algorithm Registry that this wallet
/// computes, weakest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlg {
    /// `sha-256`, which every implementation supports (B.3.3.1).
    Sha256,
    /// `sha-384`.
    Sha384,
    /// `sha-512`.
    Sha512,
}

impl HashAlg {
    const ALL: [Self; 3] = [Self::Sha256, Self::Sha384, Self::Sha512];

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
    pub fn hash(self, entry: &TransactionDataItem) -> Base64Url {
        base64url::encode(&self.digest(entry.as_str().as_bytes()))
    }

    /// The digest of `bytes`.
    pub(crate) fn digest(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(bytes).to_vec(),
            Self::Sha384 => Sha384::digest(bytes).to_vec(),
            Self::Sha512 => Sha512::digest(bytes).to_vec(),
        }
    }

    /// The length of a digest, in bytes.
    pub(crate) fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The algorithm the Hash Name String `name` names.
    fn named(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.identifier() == name)
    }

    /// The algorithm the W3C Subresource Integrity token `token` names (SRI, Section 3.2),
    /// compared without regard to ASCII case.
    pub(crate) fn sri_named(token: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|alg| alg.sri_token().eq_ignore_ascii_case(token))
    }

    /// The token of the algorithm in SRI.
    fn sri_token(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
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
pub(crate) const HASHES_ALG: MemberPath = MemberPath::new("transaction_data_hashes_alg");

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
        let names = names
            .into_iter()
            .map(|name| json::text(name, HASHES_ALG))
            .collect::<Result<Vec<_>, _>>()?;
        let algs: Vec<HashAlg> = names
            .iter()
            .filter_map(|name| HashAlg::named(name))
            .collect();
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

    /// The claim the KB-JWT carries for the request's `transaction_data_hashes_alg`.
    fn claim(&self) -> AlgClaim {
        match self {
            Self::Default => AlgClaim::Omitted,
            Self::Listed(_) => AlgClaim::Repeated,
        }
    }
}

/// Whether a KB-JWT carries `transaction_data_hashes_alg` (B.3.3.1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AlgClaim {
    /// An entry bound to the credential carried the member: the KB-JWT repeats the algorithm.
    Repeated,
    /// No entry carried it.
    Omitted,
}

/// The algorithm of one KB-JWT, shared by the entries bound to its credential (B.3.3.1).
#[derive(Clone, Copy)]
pub(crate) struct Choice {
    alg: HashAlg,
    claim: AlgClaim,
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
        let repeated = accepted.iter().any(|a| a.claim() == AlgClaim::Repeated);
        Ok(Self {
            alg,
            claim: if repeated {
                AlgClaim::Repeated
            } else {
                AlgClaim::Omitted
            },
        })
    }

    /// The algorithm.
    pub(crate) fn alg(self) -> HashAlg {
        self.alg
    }

    /// Whether the KB-JWT carries `transaction_data_hashes_alg`: when any entry bound to the
    /// credential carried it (B.3.3.1).
    pub(crate) fn claim(self) -> AlgClaim {
        self.claim
    }
}
