//! The wallet's tests of a nym_auth candidate (A2; N3, N4): a usable attestation at the proof
//! time, the `secret_seed` its issuer delivered, and an option it answers.

use std::fmt;

use itertools::Itertools;
use siros_codec::date::DateTime;
use siros_credential::{Parsed, UsableCredential};
use siros_zkp_req_nym_auth::attestation::{SecretSeed, Unreadable, Unusable, UsableAttestation};
use siros_zkp_req_nym_auth::outcome::CredentialCode;
use siros_zkp_req_nym_auth::presenter::{Answer as NymAnswer, Unanswerable};

use super::seed::{self, NoSeed};
use crate::error::PresentationError;
use crate::matching::{ChoiceError, ProofChoice, ZkpQuery};

/// Why a nym_auth candidate answers no option of its query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unproven {
    /// The credential is no mdoc.
    NotAnMdoc,
    /// The mdoc is of another `docType`.
    OtherDocType,
    /// The credential cannot be read in the nym_auth form: `credential_form`.
    Unreadable(Unreadable),
    /// The MSO lists another digest of an element, or none: `issuer_signature`.
    Unlisted,
    /// The credential fails these tests at the proof time.
    Fails(Vec<CredentialCode>),
    /// The issuer delivered no usable `secret_seed`.
    Seed(NoSeed),
    /// Each option with a usable pair refuses the credential, in the Verifier's order.
    Options(Vec<OptionRefusal>),
}

/// Why a credential answers an option of a nym_auth query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionRefusal {
    /// The option's pair is not usable again.
    Choice(ChoiceError),
    /// An item of the option fails for the credential.
    Unanswerable(Unanswerable),
}

impl Unproven {
    /// A stable identifier: the code of the test that failed, `credential` for several, or
    /// `no_option_answered`.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAnMdoc => "not_an_mdoc",
            Self::OtherDocType => "other_doc_type",
            Self::Unreadable(_) => CredentialCode::CredentialForm.code(),
            Self::Unlisted => CredentialCode::IssuerSignature.code(),
            Self::Fails(_) => "credential",
            Self::Seed(e) => e.code(),
            Self::Options(_) => "no_option_answered",
        }
    }
}

impl fmt::Display for Unproven {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for Unproven {}

impl From<Unusable> for Unproven {
    fn from(unusable: Unusable) -> Self {
        match unusable {
            Unusable::OtherDocType => Self::OtherDocType,
            Unusable::Unreadable(unreadable) => Self::Unreadable(unreadable),
            Unusable::Unlisted => Self::Unlisted,
            Unusable::Fails(failures) => Self::Fails(failures.codes().to_vec()),
        }
    }
}

impl From<NoSeed> for Unproven {
    fn from(error: NoSeed) -> Self {
        Self::Seed(error)
    }
}

/// The first of `zkp`'s choices `credential` answers at `now`, in the Verifier's order.
///
/// # Errors
///
/// [`Unproven`]: the credential's failed tests, its seed, or the refusal of every option.
pub(super) fn first_answered(
    credential: &UsableCredential<'_>,
    zkp: &ZkpQuery,
    now: DateTime,
) -> Result<ProofChoice, Unproven> {
    let (attestation, seed) = tested(credential, zkp, now)?;
    let (answered, refusals): (Vec<ProofChoice>, Vec<OptionRefusal>) = zkp
        .choices()
        .iter()
        .map(|choice| {
            let pair = zkp.pair(choice).map_err(OptionRefusal::Choice)?;
            NymAnswer::new(pair, attestation.clone(), &seed)
                .map(|_answer| choice.clone())
                .map_err(OptionRefusal::Unanswerable)
        })
        .partition_result();
    answered
        .into_iter()
        .next()
        .ok_or(Unproven::Options(refusals))
}

/// The answer of `choice` by `credential` at `now`, which opens the attestation's `ssc` again
/// for this use.
///
/// # Errors
///
/// [`PresentationError`]: the credential's failed tests or seed, a choice that gives no usable
/// pair, or an item of the option that fails.
pub(crate) fn nym_answer<'z>(
    credential: &UsableCredential<'_>,
    zkp: &'z ZkpQuery,
    choice: &ProofChoice,
    now: DateTime,
) -> Result<NymAnswer<'z>, PresentationError> {
    let (attestation, seed) = tested(credential, zkp, now)?;
    Ok(NymAnswer::new(zkp.pair(choice)?, attestation, &seed)?)
}

/// The usable attestation of `credential`'s mdoc for `zkp` at `now`, and the `secret_seed` its
/// issuer delivered.
fn tested(
    credential: &UsableCredential<'_>,
    zkp: &ZkpQuery,
    now: DateTime,
) -> Result<(UsableAttestation, SecretSeed), Unproven> {
    let Parsed::Mdoc(mdoc) = credential.credential().parsed() else {
        return Err(Unproven::NotAnMdoc);
    };
    // No input resolves `trusted_authorities` to anchors: a query that names authorities finds
    // every issuer untrusted.
    let anchors = zkp
        .query()
        .query()
        .trusted_authorities
        .as_ref()
        .map(|_| &[][..]);
    let attestation = UsableAttestation::of(mdoc, anchors, now)?;
    let seed = seed::delivered(credential.credential())?;
    Ok((attestation, seed))
}
