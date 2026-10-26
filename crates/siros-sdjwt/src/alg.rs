//! The hash algorithms `_sd_alg` may name (RFC 9901, Sections 4.1.1 and 9.4).

use sha2::{Digest, Sha256, Sha384, Sha512};
use siros_codec::base64url;

/// A hash algorithm of the IANA "Named Information Hash Algorithm" registry that Section 9.4
/// deems fit. The truncated `sha-256-*` entries are unfit.
#[derive(Clone, Copy)]
pub(crate) enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// The algorithm of the case-sensitive Hash Name String `name`.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            "sha-256" => Some(Self::Sha256),
            "sha-384" => Some(Self::Sha384),
            "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The base64url digest of `input` (Section 4.2.3).
    pub(crate) fn digest(self, input: &[u8]) -> String {
        match self {
            Self::Sha256 => base64url::encode(&Sha256::digest(input)).into(),
            Self::Sha384 => base64url::encode(&Sha384::digest(input)).into(),
            Self::Sha512 => base64url::encode(&Sha512::digest(input)).into(),
        }
    }
}
