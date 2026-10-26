//! A DCQL query whose members parsed, before the uniqueness rules of §6.1 and §6.3; and the
//! typed error of a member that breaks its rule.

use serde::Deserialize;
use serde_json::Value;

use super::{CredentialQuery, CredentialSetQuery, DcqlQuery, QueryError};
use crate::authority::TrustedAuthorities;
use crate::id::{ClaimId, QueryId};

/// A DCQL query (§6) whose identifiers may repeat.
#[derive(Deserialize)]
pub(super) struct Unchecked {
    credentials: Vec<CredentialQuery>,
    #[serde(default)]
    credential_sets: Option<Vec<CredentialSetQuery>>,
}

impl TryFrom<Unchecked> for DcqlQuery {
    type Error = QueryError;

    /// The query, when no two credential queries share an `id` (§6.1) and no two claims queries
    /// of one credential query do (§6.3).
    ///
    /// Each id is compared with the earlier ones: a hash set would add its table code to
    /// `matcher.wasm`, which holds no other.
    fn try_from(query: Unchecked) -> Result<Self, QueryError> {
        for (position, credential) in query.credentials.iter().enumerate() {
            let earlier = query.credentials.iter().take(position);
            if earlier.map(|c| &c.id).any(|id| *id == credential.id) {
                return Err(QueryError::DuplicateCredentialId(credential.id.clone()));
            }
            for (position, claim) in credential.claims.iter().enumerate() {
                let mut earlier = credential.claims.iter().take(position);
                if let Some(id) = claim
                    .id
                    .as_ref()
                    .filter(|id| earlier.any(|c| c.id.as_ref() == Some(id)))
                {
                    return Err(QueryError::DuplicateClaimId {
                        credential: credential.id.clone(),
                        claim: id.clone(),
                    });
                }
            }
        }
        Ok(Self {
            credentials: query.credentials,
            credential_sets: query.credential_sets,
        })
    }
}

/// The first rule of a typed member that `document` breaks: a Credential Query `id`, a claims
/// query `id`, `trusted_authorities`, or an id a `claim_sets` or `credential_sets` option
/// names, in the order of the document. A member of another type than its rule reads is left
/// to the deserialisation.
pub(super) fn typed_error(document: &Value) -> Option<QueryError> {
    let credentials = members(document.get("credentials"));
    let sets = members(document.get("credential_sets"));
    credentials.iter().find_map(credential_error).or_else(|| {
        sets.iter()
            .flat_map(|set| members(set.get("options")))
            .flat_map(|option| strings(Some(option)))
            .find_map(|id| QueryId::parse(id).err())
            .map(QueryError::Id)
    })
}

/// The first rule of a typed member the Credential Query `credential` breaks.
fn credential_error(credential: &Value) -> Option<QueryError> {
    let id = match QueryId::parse(credential.get("id")?.as_str()?) {
        Ok(id) => id,
        Err(error) => return Some(QueryError::Id(error)),
    };
    let mut claim_ids = members(credential.get("claims"))
        .iter()
        .filter_map(|claim| claim.get("id")?.as_str())
        .chain(
            members(credential.get("claim_sets"))
                .iter()
                .flat_map(|set| strings(Some(set))),
        );
    let claim_error = claim_ids.find_map(|text| ClaimId::parse(text).err());
    if let Some(error) = claim_error {
        return Some(QueryError::ClaimId {
            credential: id,
            error,
        });
    }
    let authorities = credential
        .get("trusted_authorities")
        .filter(|value| !value.is_null())?;
    TrustedAuthorities::parse(authorities)
        .err()
        .map(|error| QueryError::TrustedAuthorities {
            credential: id,
            error,
        })
}

/// The elements of an array member; none for another member.
fn members(value: Option<&Value>) -> &[Value] {
    value.and_then(Value::as_array).map_or(&[], Vec::as_slice)
}

/// The string elements of an array member.
fn strings(value: Option<&Value>) -> impl Iterator<Item = &str> {
    members(value).iter().filter_map(Value::as_str)
}
