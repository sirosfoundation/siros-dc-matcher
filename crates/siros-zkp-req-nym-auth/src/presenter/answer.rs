//! The answer of an option: a usable pair, a usable attestation and the seed that opens it, for
//! which every item of the option holds (system rulebooks, Section 7, step 1).

use std::fmt;

use crate::attestation::{OpenedSeed, SeedMismatch, UsableAttestation};
use crate::outcome::{ItemCode, ZkpError};
use crate::pair::{failed_assertions, UsablePair};

/// What the proof of an option needs: a usable pair for it, a usable attestation at the pair's
/// proof date, and the `secret_seed` that opens the attestation's `ssc`. Every assertion of the
/// option holds for the attestation.
#[derive(Debug, Clone)]
pub struct Answer<'q> {
    pair: UsablePair<'q>,
    attestation: UsableAttestation,
    seed: OpenedSeed,
}

/// Why an attestation does not answer an option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unanswerable {
    /// The attestation was tested at another date than the pair's proof date.
    ProofDate,
    /// Items of the option fail for the attestation: an assertion, or the `pseudonym`'s seed.
    Failed(Vec<ZkpError>),
}

impl Unanswerable {
    /// A stable identifier: `proof_date`, or `credential` for failed items, with their codes in
    /// the variant.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ProofDate => "proof_date",
            Self::Failed(_) => "credential",
        }
    }
}

impl fmt::Display for Unanswerable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Unanswerable {}

impl<'q> Answer<'q> {
    /// The answer of `pair`'s option by `attestation`, whose `ssc` `secret_seed` opens. The
    /// seed is opened again here, for this use (privatedata, Section 5A.2).
    ///
    /// # Errors
    ///
    /// [`Unanswerable::ProofDate`] for an attestation tested at another date than the pair's,
    /// and [`Unanswerable::Failed`] with the `age_check` that fails and `seed_mismatch` for a
    /// seed that does not open `ssc`.
    pub fn new(
        pair: UsablePair<'q>,
        attestation: UsableAttestation,
        secret_seed: &[u8; 16],
    ) -> Result<Self, Unanswerable> {
        if attestation.proof_time().date() != pair.date() {
            return Err(Unanswerable::ProofDate);
        }
        let option = pair.option().option();
        let birth_date = *attestation.credential().mdoc().birth_date().value();
        let mut errors =
            failed_assertions(pair.option().query(), option, pair.bounds(), birth_date);
        let seed = match OpenedSeed::open(attestation.credential(), secret_seed) {
            Ok(seed) => Some(seed),
            Err(SeedMismatch) => {
                errors.push(ZkpError::Item {
                    option: option.req_set,
                    item: pair.pseudonym().0,
                    code: ItemCode::SeedMismatch,
                });
                None
            }
        };
        match seed {
            Some(seed) if errors.is_empty() => Ok(Self {
                pair,
                attestation,
                seed,
            }),
            _ => Err(Unanswerable::Failed(errors)),
        }
    }

    /// The usable pair.
    pub fn pair(&self) -> &UsablePair<'q> {
        &self.pair
    }

    /// The usable attestation.
    pub fn attestation(&self) -> &UsableAttestation {
        &self.attestation
    }

    pub(crate) fn into_parts(self) -> (UsablePair<'q>, UsableAttestation, OpenedSeed) {
        (self.pair, self.attestation, self.seed)
    }
}
