//! Path validation as TR3 restricts RFC 5280, Section 6.1: an issuer chain's first certificate
//! has a path to an anchor certificate at a given time.
//!
//! A path is a prefix of the chain, each certificate signed by the next, whose last certificate
//! an anchor signs. Each signer names its subject as the certificate's issuer and is a CA, and
//! every certificate on the path, the anchor included, is valid at the time. Signatures are
//! ECDSA P-256 with SHA-256 or P-384 with SHA-384, over the `tbsCertificate` as written. Name
//! constraints, policies, key usage, path length and revocation are outside TR3.

use std::fmt;

use siros_codec::date::DateTime;

use crate::certificate::{Certificate, CertificateRole, IssuanceRefusal};
use crate::chain::IssuerChain;
use crate::position::{CertificateIndex, ChainIndex};

/// A certificate on a validation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnPath {
    /// A certificate of the issuer chain.
    Chain(ChainIndex),
    /// An anchor certificate.
    Store(CertificateIndex),
}

/// Why an issuer chain has no path to an anchor certificate. It names the attempt it refuses:
/// the deepest prefix of the chain tried, and there the first anchor tried, when one has the
/// subject the prefix's last certificate names as its issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathRefusal {
    /// The certificate is not valid at the time.
    NotValid(OnPath),
    /// No anchor, nor the chain's next certificate, has the subject the chain's certificate
    /// names as its issuer.
    IssuerName(ChainIndex),
    /// The signer is not a CA: its basicConstraints is absent or its `cA` is FALSE.
    NotCa(OnPath),
    /// The chain's certificate is signed with an algorithm other than `ecdsa-with-SHA256` and
    /// `ecdsa-with-SHA384`.
    Algorithm(ChainIndex),
    /// The signer's key is of another type or curve than the certificate's signature algorithm
    /// takes.
    IssuerKey {
        /// The certificate.
        certificate: ChainIndex,
        /// Its signer.
        signer: OnPath,
    },
    /// The certificate's signature is no DER `ECDSA-Sig-Value` of the signer's curve.
    SignatureEncoding {
        /// The certificate.
        certificate: ChainIndex,
        /// Its signer.
        signer: OnPath,
    },
    /// The certificate's signature does not verify under the signer's key.
    Signature {
        /// The certificate.
        certificate: ChainIndex,
        /// Its signer.
        signer: OnPath,
    },
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
            Self::IssuerKey { .. } => "path_issuer_key",
            Self::SignatureEncoding { .. } => "path_signature_encoding",
            Self::Signature { .. } => "path_signature",
        }
    }
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self:?}", self.code())
    }
}

impl std::error::Error for PathRefusal {}

/// A validated path (TR3): the chain's certificates up to `anchored_at`, each signed by the
/// next, the last signed by the anchor at `anchor`, all valid at the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrustPath {
    anchored_at: ChainIndex,
    anchor: CertificateIndex,
}

/// A signer on a path, with its position.
#[derive(Clone, Copy)]
struct Signer<'c> {
    certificate: &'c Certificate,
    position: OnPath,
}

impl TrustPath {
    /// The path from `chain`'s first certificate up to one of `anchors` at `time`.
    ///
    /// Each prefix of the chain is tried, shortest first, and at each the anchors whose subject
    /// its last certificate names as its issuer, the one whose SubjectKeyIdentifier equals the
    /// certificate's AuthorityKeyIdentifier first.
    ///
    /// # Errors
    ///
    /// [`PathRefusal`]: why the deepest attempt fails.
    pub fn new(
        chain: &IssuerChain,
        anchors: &[Certificate],
        time: DateTime,
    ) -> Result<Self, PathRefusal> {
        let certificates: Vec<&Certificate> = chain.certificates().collect();
        let mut position = 0;
        let mut certificate = chain.leaf();
        loop {
            let at = ChainIndex::new(position);
            if !certificate.valid_at(time) {
                return Err(PathRefusal::NotValid(OnPath::Chain(at)));
            }
            let refusal = match anchored(certificate, at, anchors, time) {
                Ok(anchor) => {
                    return Ok(Self {
                        anchored_at: at,
                        anchor,
                    })
                }
                Err(refusal) => refusal,
            };
            let next = certificates.get(position + 1).copied();
            certificate = match next_link(certificate, at, next, time) {
                Ok(next) => next,
                Err(extension) => return Err(refusal.unwrap_or(extension)),
            };
            position += 1;
        }
    }

    /// The position of the path's last chain certificate, the one the anchor signs.
    #[must_use]
    pub fn anchored_at(self) -> ChainIndex {
        self.anchored_at
    }

    /// The position of the anchor among the anchors.
    #[must_use]
    pub fn anchor(self) -> CertificateIndex {
        self.anchor
    }
}

/// The anchor that signs `certificate`, at `at` on the chain; else the refusal of the first
/// anchor tried, or `None` when no anchor has the subject `certificate` names as its issuer.
fn anchored(
    certificate: &Certificate,
    at: ChainIndex,
    anchors: &[Certificate],
    time: DateTime,
) -> Result<CertificateIndex, Option<PathRefusal>> {
    let mut named: Vec<(CertificateIndex, &Certificate)> = anchors
        .iter()
        .enumerate()
        .filter(|(_, anchor)| certificate.names_as_issuer(anchor))
        .map(|(index, anchor)| (CertificateIndex::new(index), anchor))
        .collect();
    let keyed = |anchor: &Certificate| {
        certificate.authority_key_identifier().is_some()
            && certificate.authority_key_identifier() == anchor.subject_key_identifier()
    };
    named.sort_by_key(|(_, anchor)| !keyed(anchor));
    let mut first = None;
    for (index, anchor) in named {
        let signer = Signer {
            certificate: anchor,
            position: OnPath::Store(index),
        };
        match link(certificate, at, signer, time) {
            Ok(()) => return Ok(index),
            Err(refusal) => {
                if first.is_none() {
                    first = Some(refusal);
                }
            }
        }
    }
    Err(first)
}

/// `next`, the chain's next certificate, when it signs `certificate` at `at`.
fn next_link<'c>(
    certificate: &Certificate,
    at: ChainIndex,
    next: Option<&'c Certificate>,
    time: DateTime,
) -> Result<&'c Certificate, PathRefusal> {
    let next = next
        .filter(|next| certificate.names_as_issuer(next))
        .ok_or(PathRefusal::IssuerName(at))?;
    let signer = Signer {
        certificate: next,
        position: OnPath::Chain(ChainIndex::new(at.value() + 1)),
    };
    link(certificate, at, signer, time).map(|()| next)
}

/// Whether `signer` signs `certificate`, at `at` on the chain: an anchor valid at `time`, a CA,
/// that issued `certificate`. A chain certificate's validity is checked at its own step.
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
            IssuanceRefusal::IssuerKey => PathRefusal::IssuerKey {
                certificate: at,
                signer: signer.position,
            },
            IssuanceRefusal::SignatureEncoding => PathRefusal::SignatureEncoding {
                certificate: at,
                signer: signer.position,
            },
            IssuanceRefusal::Signature => PathRefusal::Signature {
                certificate: at,
                signer: signer.position,
            },
        })
}
