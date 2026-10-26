//! Path validation as TR3 restricts RFC 5280, Section 6.1: an issuer chain's first certificate
//! validates up to a certificate of a trust store entry at a given time.
//!
//! Each certificate on the path is signed by the next one or by the store certificate, names its
//! signer as its issuer, and is valid at the time; every signer is a CA. The store certificate
//! counts as a certificate on the path: its validity and its `cA` are checked as well.
//! Signatures are ECDSA P-256 with SHA-256 or P-384 with SHA-384. Name constraints, policies,
//! key usage, path length and revocation are outside TR3.

use std::fmt;

use siros_codec::date::DateTime;

use crate::certificate::{Certificate, CertificateRole, IssuanceRefusal};
use crate::chain::IssuerChain;
use crate::position::{CertificateIndex, ChainIndex};
use crate::store::StoreEntry;

/// A certificate on a validation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnPath {
    /// A certificate of the issuer chain.
    Chain(ChainIndex),
    /// A certificate of the trust store entry.
    Store(CertificateIndex),
}

/// Why an issuer chain does not validate up to a trust store entry's certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathRefusal {
    /// The certificate is not valid at the time.
    NotValid(OnPath),
    /// The chain's certificate names as its issuer neither the next certificate of the chain
    /// nor a certificate of the entry.
    IssuerName(ChainIndex),
    /// The signer is not a CA: its basicConstraints is absent or its `cA` is FALSE.
    NotCa(OnPath),
    /// The chain's certificate is signed with another algorithm than ECDSA P-256 with SHA-256
    /// or P-384 with SHA-384 under its signer's key.
    Algorithm(ChainIndex),
    /// The chain's certificate's signature does not verify under its signer's key.
    Signature(ChainIndex),
}

impl PathRefusal {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotValid(_) => "path_not_valid",
            Self::IssuerName(_) => "path_issuer_name",
            Self::NotCa(_) => "path_signer_not_ca",
            Self::Algorithm(_) => "path_signature_algorithm",
            Self::Signature(_) => "path_signature",
        }
    }
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for PathRefusal {}

/// A signer on a path, with its position.
#[derive(Clone, Copy)]
struct Signer<'c> {
    certificate: &'c Certificate,
    position: OnPath,
}

impl StoreEntry {
    /// Whether `chain`'s first certificate validates up to one of the entry's certificates at
    /// `time` (TR3).
    ///
    /// The path follows the names: a certificate whose issuer is the subject of a certificate
    /// of the entry is signed by it; another is signed by the next certificate of the chain.
    ///
    /// # Errors
    ///
    /// [`PathRefusal`]: the first rule the path breaks. Among several certificates of the
    /// entry that a certificate names, the refusal is the first one's.
    pub fn validates(&self, chain: &IssuerChain, time: DateTime) -> Result<(), PathRefusal> {
        let mut certificate = chain.leaf();
        let mut issuers = chain.issuers();
        let mut position = 0;
        loop {
            let at = ChainIndex::new(position);
            if !certificate.valid_at(time) {
                return Err(PathRefusal::NotValid(OnPath::Chain(at)));
            }
            let anchors: Vec<Signer<'_>> = self
                .certificates()
                .iter()
                .enumerate()
                .filter(|(_, anchor)| certificate.names_as_issuer(anchor))
                .map(|(index, anchor)| Signer {
                    certificate: anchor,
                    position: OnPath::Store(CertificateIndex::new(index)),
                })
                .collect();
            if let Some((first, others)) = anchors.split_first() {
                return first_link(certificate, at, *first, others, time);
            }
            let Some((next, rest)) = issuers
                .split_first()
                .filter(|(next, _)| certificate.names_as_issuer(next))
            else {
                return Err(PathRefusal::IssuerName(at));
            };
            position += 1;
            let signer = Signer {
                certificate: next,
                position: OnPath::Chain(ChainIndex::new(position)),
            };
            link(certificate, at, signer, time)?;
            certificate = next;
            issuers = rest;
        }
    }
}

/// Whether `first` or one of `others` signs `certificate`, at `at` on the chain.
///
/// # Errors
///
/// The refusal of `first` when none signs it.
fn first_link(
    certificate: &Certificate,
    at: ChainIndex,
    first: Signer<'_>,
    others: &[Signer<'_>],
    time: DateTime,
) -> Result<(), PathRefusal> {
    let refusal = match link(certificate, at, first, time) {
        Ok(()) => return Ok(()),
        Err(refusal) => refusal,
    };
    if others
        .iter()
        .any(|signer| link(certificate, at, *signer, time).is_ok())
    {
        Ok(())
    } else {
        Err(refusal)
    }
}

/// Whether `signer` signs `certificate`, at `at` on the chain: a store certificate valid at
/// `time`, a CA, that issued `certificate`. The validity of a chain certificate is checked at
/// its own step.
fn link(
    certificate: &Certificate,
    at: ChainIndex,
    signer: Signer<'_>,
    time: DateTime,
) -> Result<(), PathRefusal> {
    if matches!(signer.position, OnPath::Store(_)) && !signer.certificate.valid_at(time) {
        return Err(PathRefusal::NotValid(signer.position));
    }
    if signer.certificate.role() != CertificateRole::Ca {
        return Err(PathRefusal::NotCa(signer.position));
    }
    certificate
        .issued_by(signer.certificate)
        .map_err(|refusal| match refusal {
            IssuanceRefusal::IssuerName => PathRefusal::IssuerName(at),
            IssuanceRefusal::Algorithm => PathRefusal::Algorithm(at),
            IssuanceRefusal::Signature => PathRefusal::Signature(at),
        })
}
