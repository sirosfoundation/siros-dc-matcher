//! `match`: one query against the Wallet's credentials (`zkp_req`, Sections 1.3 and 2.1).

use serde_json::Value;
use siros_codec::date::DateTime;
use siros_zkp_req::{Candidate, Judged, Match, OptionRefusal, PairRefusal};

use super::{
    anchors_for, credential_errors, item_errors, parse, plan_option, HostError, OptionPlan,
};
use crate::attestation::{Unusable, UsableAttestation};
use crate::catalogue::NymAuthQuery;
use crate::mdoc::StoredCredential;
use crate::outcome::{InvalidRequest, ZkpError};
use crate::system::{NymAuthSystem, Unsupported};

/// The outcome of matching one nym_auth query.
pub type NymAuthMatch = Match<InvalidRequest, PairRefusal<Unsupported>, ZkpError>;

/// What `match` needs: the request's query and metadata, and what the host's `WalletContext`
/// gives.
#[derive(Debug, Clone, Copy)]
pub struct MatchInput<'a> {
    /// The Credential Query, one element of `dcql_query.credentials`.
    pub query: &'a Value,
    /// The request's `client_metadata`.
    pub client_metadata: &'a Value,
    /// The Wallet's credentials of the query's format and type; a superset is fine.
    pub credentials: &'a [StoredCredential],
    /// DER certificates of the anchors the query's `trusted_authorities` designate. Required
    /// when the query has `trusted_authorities`.
    pub anchors: Option<&'a [Vec<u8>]>,
    /// The systems the host proves, in the Wallet's order of preference.
    pub systems: &'a [NymAuthSystem],
    /// The Wallet's clock: seconds since 1970-01-01T00:00:00Z. The proof time.
    pub now: i64,
}

/// A stored credential and its usable attestation at the proof time, or why it has none.
type Tested<'c> = (&'c StoredCredential, Result<UsableAttestation, Unusable>);

/// Matches one query against the Wallet's credentials (`zkp_req`, Sections 1.3 and 2.1).
///
/// The candidates come in the Verifier's order of options, then in the order of
/// `credentials`. Each answers its option with the first usable pair in the Wallet's order.
///
/// # Errors
///
/// [`HostError`]: an input of the host this presenter cannot use.
pub fn match_query(input: &MatchInput<'_>) -> Result<NymAuthMatch, HostError> {
    let proof_time = DateTime::from_unix(input.now).ok_or(HostError::Time)?;
    let parsed = match parse(input.query, input.client_metadata) {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return Ok(Match::Rejected(Vec::new())),
        Err(rule) => return Ok(Match::Invalid(rule)),
    };
    let d = proof_time.date();
    let plans: Vec<OptionPlan<'_>> = parsed
        .query
        .options()
        .map(|option| plan_option(&parsed, option, input.systems, d))
        .collect();
    if plans.iter().all(|p| p.pair.is_none()) {
        return Ok(Match::Unsupported(unsupported(plans)));
    }
    let anchors = anchors_for(&parsed.query, input.anchors)?;
    let tested: Vec<Tested<'_>> = input
        .credentials
        .iter()
        .filter(|c| c.format == "mso_mdoc")
        .map(|c| (c, UsableAttestation::new(&c.data, anchors, proof_time)))
        .collect();
    Ok(candidates_or_rejections(&parsed.query, &plans, &tested))
}

fn unsupported(plans: Vec<OptionPlan<'_>>) -> Vec<OptionRefusal<PairRefusal<Unsupported>>> {
    plans
        .into_iter()
        .map(|p| OptionRefusal {
            req_set: p.option.req_set,
            systems: p.refusals,
        })
        .collect()
}

/// The outcome for one credential and one option with a usable pair. `None` for an mdoc of
/// another `docType`.
fn judge(
    query: &NymAuthQuery,
    plan: &OptionPlan<'_>,
    tested: &Result<UsableAttestation, Unusable>,
) -> Option<Result<(), Vec<ZkpError>>> {
    let (mut errors, credential) = credential_errors(tested)?;
    if let Some(credential) = credential {
        errors.extend(item_errors(query, plan, credential));
    }
    Some(if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    })
}

fn candidates_or_rejections(
    query: &NymAuthQuery,
    plans: &[OptionPlan<'_>],
    tested: &[Tested<'_>],
) -> NymAuthMatch {
    let mut candidates = Vec::new();
    let mut rejected: Vec<Judged<ZkpError>> = Vec::new();
    for plan in plans {
        let Some(pair) = &plan.pair else {
            continue;
        };
        for (credential, attestation) in tested {
            match judge(query, plan, attestation) {
                Some(Ok(())) => candidates.push(Candidate {
                    credential_id: credential.id.clone(),
                    system_id: pair.system().id().to_owned(),
                    proof_backend: pair.backend().as_str().to_owned(),
                    req_set: plan.option.req_set,
                    items: plan.option.items.clone(),
                    inputs: Vec::new(),
                }),
                Some(Err(errors)) => record(&mut rejected, &credential.id, errors),
                None => {}
            }
        }
    }
    if candidates.is_empty() {
        Match::Rejected(rejected)
    } else {
        Match::Candidates(candidates)
    }
}

/// Adds `errors` to the judgement of `credential_id`, each error once.
fn record(rejected: &mut Vec<Judged<ZkpError>>, credential_id: &str, errors: Vec<ZkpError>) {
    let index = match rejected
        .iter()
        .position(|j| j.credential_id == credential_id)
    {
        Some(index) => index,
        None => {
            rejected.push(Judged {
                credential_id: credential_id.to_owned(),
                errors: Vec::new(),
            });
            rejected.len() - 1
        }
    };
    if let Some(judged) = rejected.get_mut(index) {
        for error in errors {
            if !judged.errors.contains(&error) {
                judged.errors.push(error);
            }
        }
    }
}
