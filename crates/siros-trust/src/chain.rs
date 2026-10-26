//! A credential's issuer chain (TR2): the certificates the credential carries for its issuer,
//! the signer's first.

use std::fmt;

use crate::authority::KeyIdentifier;
use crate::certificate::{Certificate, CertificateError};
use crate::position::ChainIndex;

/// An issuer chain: at least one certificate, the signer's first. The mdoc `x5chain` or the
/// SD-JWT VC issuer-signed JWT's `x5c`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerChain {
    leaf: Certificate,
    issuers: Vec<Certificate>,
}

/// Why certificates are no issuer chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainError {
    /// The chain holds no certificate.
    Empty,
    /// A certificate does not parse.
    Certificate {
        /// Its position.
        position: ChainIndex,
        /// Why.
        error: CertificateError,
    },
}

impl ChainError {
    /// A stable identifier: `issuer_chain_empty`, or the certificate's code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Empty => "issuer_chain_empty",
            Self::Certificate { error, .. } => error.code(),
        }
    }
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str(self.code()),
            Self::Certificate { position, error } => {
                write!(f, "{error} at {}", position.value())
            }
        }
    }
}

impl std::error::Error for ChainError {}

impl IssuerChain {
    /// The chain of the DER certificates `certificates`, the signer's first.
    ///
    /// # Errors
    ///
    /// [`ChainError`]: no certificate, or the first that does not parse.
    pub fn parse<'a>(certificates: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, ChainError> {
        let mut parsed = certificates.into_iter().enumerate().map(|(position, der)| {
            Certificate::parse(der).map_err(|error| ChainError::Certificate {
                position: ChainIndex::new(position),
                error,
            })
        });
        let leaf = parsed.next().ok_or(ChainError::Empty)??;
        let issuers = parsed.collect::<Result<_, _>>()?;
        Ok(Self { leaf, issuers })
    }

    /// The certificates, the signer's first.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        std::iter::once(&self.leaf).chain(&self.issuers)
    }

    /// The chain's first certificate: the signer's.
    #[must_use]
    pub fn leaf(&self) -> &Certificate {
        &self.leaf
    }

    /// The certificates after the first, in the chain's order.
    pub(crate) fn issuers(&self) -> &[Certificate] {
        &self.issuers
    }

    /// The keyIdentifiers the chain's AuthorityKeyIdentifier extensions name, in the chain's
    /// order.
    pub fn key_identifiers(&self) -> impl Iterator<Item = &KeyIdentifier> {
        self.certificates()
            .filter_map(Certificate::authority_key_identifier)
    }
}
