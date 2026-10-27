//! The wallet's tests of a nym_auth candidate (A2; N3, N4): a usable attestation at the proof
//! time, the `secret_seed` its issuer delivered, and an option it answers.

use itertools::Itertools;
use siros_codec::date::DateTime;
use siros_credential::{Parsed, UsableCredential};
use siros_zkp_req_nym_auth::attestation::{SecretSeed, Unreadable, Unusable, UsableAttestation};
use siros_zkp_req_nym_auth::outcome::CredentialCode;
use siros_zkp_req_nym_auth::presenter::{Answer as NymAnswer, Unanswerable};

use super::seed::{self, NoSeed};
use crate::matching::{ChoiceError, ProofChoice, ZkpQuery};

/// Why a nym_auth candidate answers no option of its query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum Unproven {
    /// The credential is no mdoc.
    NotAnMdoc,
    /// The mdoc is of another `docType`.
    OtherDocType,
    /// The credential cannot be read in the nym_auth form: `credential_form`.
    Unreadable(#[source] Unreadable),
    /// The MSO lists another digest of an element, or none: `issuer_signature`.
    Unlisted,
    /// The credential fails these tests at the proof time.
    Fails(Vec<CredentialCode>),
    /// The issuer delivered no usable `secret_seed`.
    Seed(#[from] NoSeed),
    /// Each option with a usable pair refuses the credential, in the Verifier's order.
    Options(Vec<OptionRefusal>),
}

/// Why a credential answers an option of a nym_auth query.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OptionRefusal {
    /// The option's pair is not usable again.
    #[error("the option's pair is not usable again")]
    Choice(#[source] ChoiceError),
    /// An item of the option fails for the credential.
    #[error("an item of the option fails for the credential")]
    Unanswerable(#[source] Unanswerable),
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
