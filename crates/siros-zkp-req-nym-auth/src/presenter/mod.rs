//! The presenter of nym_auth queries: `match`, then the Wallet's consent, then `prove`.
//!
//! It does no input or output. The host passes what its `WalletContext` holds (credentials,
//! anchors, the clock, the seed), signs the data the presenter gives it with the device key,
//! and runs a system's prover on the [`ProofJob`](crate::prover::ProofJob). The presenter keeps
//! nothing between calls: `prove` checks everything again.

mod answer;
mod matching;
mod proving;

use serde_json::Value;
use siros_codec::date::Date;
use siros_zkp_req::{PairRefusal, QueryOption, ZkpFormats, ZkpReqQuery};

pub use answer::{Answer, Unanswerable};
pub use matching::{match_query, MatchInput, NymAuthMatch};
pub use proving::{
    prepare, present, Prepared, ProveError, ProveInput, Session, SignFailure, Signer,
};

use crate::age::Bounds;
use crate::attestation::{Credential, Unusable, UsableAttestation};
use crate::catalogue::NymAuthQuery;
use crate::outcome::{InvalidRequest, ZkpError};
use crate::pair::{failed_assertions, NymAuthOption, UsablePair};
use crate::system::{NymAuthSystem, Unsupported};

/// The largest `zk_proof` the proof backends read (`longfellow-libzk-v1`, `vega-v1`).
pub const MAX_ZK_PROOF: usize = 1 << 20;

/// A host input this presenter cannot use. It is a defect of the host, never of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("host input: {}", self.code())]
pub enum HostError {
    /// `now` lies outside 0000-01-01T00:00:00Z to 9999-12-31T23:59:59Z.
    Time,
    /// The candidate names an option, system or proof backend `match` does not give.
    CandidateMismatch,
}

impl HostError {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::Time => "time",
            Self::CandidateMismatch => "candidate_mismatch",
        }
    }
}

struct Parsed {
    query: NymAuthQuery,
    formats: ZkpFormats,
}

/// The query and the metadata, read. `None` when the query asks for another credential type.
fn parse(query: &Value, client_metadata: &Value) -> Result<Option<Parsed>, InvalidRequest> {
    let parsed = ZkpReqQuery::parse(query)?;
    let formats = ZkpFormats::from_client_metadata(client_metadata)?;
    Ok(NymAuthQuery::from_query(parsed)?
        .nym_auth()
        .map(|query| Parsed { query, formats }))
}

/// An option, its bounds, and the first usable pair in the Wallet's order.
struct OptionPlan<'q> {
    option: &'q QueryOption,
    bounds: Bounds,
    pair: Option<UsablePair<'q>>,
    refusals: Vec<(String, PairRefusal<Unsupported>)>,
}

fn plan_option<'q>(
    parsed: &'q Parsed,
    option: NymAuthOption<'q>,
    systems: &[NymAuthSystem],
    d: Date,
) -> OptionPlan<'q> {
    let bounds = parsed.query.option_bounds(option.option(), d);
    let mut refusals = Vec::new();
    for &system in systems {
        match option.pair(&parsed.formats, system, d) {
            Ok(pair) => {
                return OptionPlan {
                    option: option.option(),
                    bounds,
                    pair: Some(pair),
                    refusals,
                }
            }
            Err(refusal) => refusals.push((system.id().to_owned(), refusal)),
        }
    }
    OptionPlan {
        option: option.option(),
        bounds,
        pair: None,
        refusals,
    }
}

/// The anchors to check the issuer against: required when the query names authorities.
///
/// # Panics
///
/// When the query names authorities and the host passed no anchors.
#[expect(
    clippy::panic,
    reason = "MatchInput and ProveInput require anchors when the query has \
              `trusted_authorities`; none is a bug of the host, and the issuer could not be \
              checked against the authorities the query names"
)]
fn anchors_for<'a>(query: &NymAuthQuery, anchors: Option<&'a [Vec<u8>]>) -> Option<&'a [Vec<u8>]> {
    match (&query.query().trusted_authorities, anchors) {
        (None, _) => None,
        (Some(_), Some(anchors)) => Some(anchors),
        (Some(_), None) => {
            panic!("the query names trusted authorities and the host passed no anchors")
        }
    }
}

/// The errors of the credential's failed tests, and the credential when it reads: the item
/// tests apply to it. `None` for an mdoc of another `docType`.
fn credential_errors(
    tested: &Result<UsableAttestation, Unusable>,
) -> Option<(Vec<ZkpError>, Option<&Credential>)> {
    let (codes, credential) = match tested {
        Ok(attestation) => (&[][..], Some(attestation.credential())),
        Err(Unusable::OtherDocType) => return None,
        Err(unusable) => (unusable.codes(), unusable.credential()),
    };
    let errors = codes
        .iter()
        .map(|&code| ZkpError::Credential(code))
        .collect();
    Some((errors, credential))
}

/// The items of `option` that fail for `credential`: the `age_check` assertion.
fn item_errors(
    query: &NymAuthQuery,
    plan: &OptionPlan<'_>,
    credential: &Credential,
) -> Vec<ZkpError> {
    let birth_date = *credential.mdoc().birth_date().value();
    failed_assertions(query, plan.option, &plan.bounds, birth_date)
}
