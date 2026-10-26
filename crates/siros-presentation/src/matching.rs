//! Matching (A1, A2): the candidates of each Credential Query of a request, one instance per
//! batch (C5).

mod failure;
mod zkp;

use itertools::{Either, Itertools};
use serde_json::Value;
use siros_codec::date::Date;
use siros_credential::{least_used, ClaimPointer, Format, PointerError};
use siros_dcql::eval::select_claims;
use siros_dcql::{CredentialQuery, CredentialSetQuery, DcqlQuery, PathComponent, PathError};
use siros_wallet_state::PresentationRecord;
use siros_zkp_req_nym_auth::catalogue::{BBS_SCHEMA_ID, MDOC_DOCTYPE};
use siros_zkp_req_nym_auth::policy::RequestRefusal;
use siros_zkp_req_nym_auth::system::NymAuthSystem;

use crate::credential::{KeyHolding, MatchCredential};
use crate::ids::{CandidateIndex, QueryId, QueryIndex};

pub use failure::{AskedError, Failure, QueryRefusal};
pub use zkp::{ChoiceError, ProofChoice, ZkpQuery, ZkpRefusal};

/// The types of the nym_auth attestations, whose attributes no query but `zkp_req` discloses.
const NYM_AUTH_TYPES: [&str; 2] = [MDOC_DOCTYPE, BBS_SCHEMA_ID];

/// The request as the matching reads it: its Credential Queries, each with its `id` and the
/// query as sent, its credential sets, and the Verifier metadata.
#[derive(Debug, Clone)]
pub struct Asked<'r> {
    queries: Vec<AskedQuery<'r>>,
    credential_sets: Option<&'r [CredentialSetQuery]>,
    client_metadata: Option<&'r Value>,
}

/// A Credential Query of a request, with its `id` and the query as the Verifier sent it.
#[derive(Debug, Clone)]
struct AskedQuery<'r> {
    id: QueryId,
    query: &'r CredentialQuery,
    sent: &'r Value,
}

impl<'r> Asked<'r> {
    /// The request of `query`, which the Verifier sent as `sent`, with its `client_metadata`.
    ///
    /// # Errors
    ///
    /// [`AskedError`]: a Credential Query `id` that breaks Section 6.1, or one `sent` lacks.
    pub fn new(
        query: &'r DcqlQuery,
        sent: &'r Value,
        client_metadata: Option<&'r Value>,
    ) -> Result<Self, AskedError> {
        let sent_queries: &[Value] = sent
            .get("credentials")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice);
        let queries = query
            .credentials
            .iter()
            .map(|credential| {
                let id = QueryId::parse(&credential.id).map_err(AskedError::Id)?;
                let sent = sent_queries
                    .iter()
                    .find(|c| c.get("id").and_then(Value::as_str) == Some(id.as_str()))
                    .ok_or_else(|| AskedError::Unsent(id.clone()))?;
                Ok(AskedQuery {
                    id,
                    query: credential,
                    sent,
                })
            })
            .try_collect()?;
        Ok(Self {
            queries,
            credential_sets: query.credential_sets.as_deref(),
            client_metadata,
        })
    }
}

/// What a member of an offer answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The claims an SD-JWT VC or an mdoc discloses.
    Claims(Claims),
    /// The proof of a `zkp_req` option.
    Proof(ProofChoice),
}

/// The claims a member discloses: the pointers of the claims DCQL selected (OpenID4VP 1.0,
/// Section 6.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pointers: Vec<ClaimPointer>,
    holder_binding: HolderBinding,
}

/// Whether a Credential Query requires cryptographic holder binding (OpenID4VP 1.0, Section
/// 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HolderBinding {
    /// The presentation proves possession of the credential's key.
    Required,
    /// The presentation may go without a proof of possession.
    Optional,
}

impl HolderBinding {
    /// What `query`'s `require_cryptographic_holder_binding` asks.
    fn of(query: &CredentialQuery) -> Self {
        if query.require_cryptographic_holder_binding {
            Self::Required
        } else {
            Self::Optional
        }
    }
}

impl Claims {
    /// The claims path pointers, in the order of the claims query; `[namespace, element]` for an
    /// mdoc.
    pub fn pointers(&self) -> &[ClaimPointer] {
        &self.pointers
    }

    /// Whether the query requires cryptographic holder binding.
    pub fn holder_binding(&self) -> HolderBinding {
        self.holder_binding
    }
}

/// The credentials that can answer each Credential Query, before the `zkp_req` credential
/// tests.
pub struct Matching<'r, C> {
    credential_sets: Option<&'r [CredentialSetQuery]>,
    queries: Vec<(AskedQuery<'r>, Outcome<C>)>,
}

enum Outcome<C> {
    Claims(Vec<(C, Claims)>),
    Proof {
        zkp: Box<ZkpQuery>,
        credentials: Vec<C>,
    },
    Refused(QueryRefusal),
}

impl<'r, C: MatchCredential + Clone> Matching<'r, C> {
    /// The matching of `asked` over `credentials`, usable at the proof date `date`.
    ///
    /// One instance of each batch is matched: the one [`least_used`] chooses from `records`
    /// (C5). The format table (A1):
    ///
    /// | Query format | Credentials | `meta` |
    /// | --- | --- | --- |
    /// | `mso_mdoc` | mdocs | `doctype_value` is the `docType` |
    /// | `dc+sd-jwt` | SD-JWT VCs | `vct_values` lists the `vct` |
    /// | `zkp_req` | of `meta.source_format`, through the nym_auth catalogue (A2) | `zkp_req.md`, Section 1.1 |
    ///
    /// Any other format matches nothing. A query that requires holder binding matches only a
    /// credential whose key the wallet holds, and an mdoc always needs its key. No query other
    /// than `zkp_req` matches a nym_auth attestation, whose attributes are undisclosable. Claims
    /// are selected by DCQL (OpenID4VP 1.0, Section 6.4.1); a selected claims path that is no
    /// pointer refuses the query. `policy` says whether the request meets the nym_auth policy;
    /// a nym_auth query of a request that does not is refused.
    pub fn new(
        asked: Asked<'r>,
        credentials: &[C],
        records: &[PresentationRecord],
        systems: &[NymAuthSystem],
        date: Date,
        policy: Result<(), RequestRefusal>,
    ) -> Self {
        let instances = least_used(credentials, records);
        let client_metadata = asked.client_metadata;
        let queries = asked
            .queries
            .into_iter()
            .map(|asked| {
                let outcome = match asked.query.format.as_str() {
                    "zkp_req" => {
                        match ZkpQuery::read(asked.sent, client_metadata, policy, systems, date) {
                            Ok(zkp) => Outcome::Proof {
                                credentials: zkp.provable(&instances),
                                zkp: Box::new(zkp),
                            },
                            Err(refusal) => Outcome::Refused(QueryRefusal::Zkp(refusal)),
                        }
                    }
                    _ => match answering(asked.query, &instances) {
                        Ok(found) => Outcome::Claims(found),
                        Err(error) => Outcome::Refused(QueryRefusal::ClaimPath(error)),
                    },
                };
                (asked, outcome)
            })
            .collect();
        Self {
            credential_sets: asked.credential_sets,
            queries,
        }
    }

    /// The answers of every query: `choose` gives the [`ProofChoice`] of each `zkp_req`
    /// candidate, one of [`ZkpQuery::choices`], or the reason the candidate answers none. The
    /// wallet applies the credential tests there (A2); the picker, which cannot, takes the
    /// first.
    pub fn answer<R>(
        self,
        mut choose: impl FnMut(&C, &ZkpQuery) -> Result<ProofChoice, R>,
    ) -> Answered<'r, C, R> {
        let queries = self
            .queries
            .into_iter()
            .map(|(asked, outcome)| match outcome {
                Outcome::Claims(found) => Answers::claims(asked, found),
                Outcome::Proof { zkp, credentials } => {
                    let (candidates, excluded) =
                        credentials.into_iter().partition_map(|credential| {
                            match choose(&credential, &zkp) {
                                Ok(choice) => Either::Left(Candidate {
                                    credential,
                                    answer: Answer::Proof(choice),
                                }),
                                Err(reason) => Either::Right(Excluded { credential, reason }),
                            }
                        });
                    Answers {
                        asked,
                        candidates,
                        zkp: Some(zkp),
                        refusal: None,
                        excluded,
                    }
                }
                Outcome::Refused(refusal) => Answers {
                    asked,
                    candidates: Vec::new(),
                    zkp: None,
                    refusal: Some(refusal),
                    excluded: Vec::new(),
                },
            })
            .collect();
        Answered {
            credential_sets: self.credential_sets,
            queries,
        }
    }
}

/// The instances of `instances` that answer `query`, each with the claims it discloses.
///
/// # Errors
///
/// [`PointerError`] for a selected claims path that is no pointer.
fn answering<C: MatchCredential + Clone>(
    query: &CredentialQuery,
    instances: &[&C],
) -> Result<Vec<(C, Claims)>, PointerError> {
    instances
        .iter()
        .map(|&credential| {
            let claims = claims(query, credential)?;
            Ok(claims.map(|claims| (credential.clone(), claims)))
        })
        .flatten_ok()
        .try_collect()
}

/// The claims `query` selects in `credential`, when the credential matches the query's format
/// and `meta` (A1) and holds every claim the query asks for; `None` when it does not answer.
///
/// # Errors
///
/// [`PointerError`] for a selected claims path that is no pointer.
fn claims<C: MatchCredential>(
    query: &CredentialQuery,
    credential: &C,
) -> Result<Option<Claims>, PointerError> {
    let holder_binding = HolderBinding::of(query);
    let Some(format) = asked_format(query, credential) else {
        return Ok(None);
    };
    let needs_key = format == Format::Mdoc || holder_binding == HolderBinding::Required;
    let undisclosable = NYM_AUTH_TYPES.contains(&credential.credential_type());
    if credential.format() != format
        || undisclosable
        || (needs_key && credential.key_holding() == KeyHolding::NotHeld)
    {
        return Ok(None);
    }
    let held = Held {
        credential,
        id: credential.entry().credential_id().to_string(),
    };
    let Some(selected) = select_claims(query, &held) else {
        return Ok(None);
    };
    let pointers = selected
        .into_iter()
        .map(|claim| ClaimPointer::parse(claim.path))
        .try_collect()?;
    Ok(Some(Claims {
        pointers,
        holder_binding,
    }))
}

/// The format `query` asks for, when its `meta` names `credential`'s type (A1).
fn asked_format<C: MatchCredential>(query: &CredentialQuery, credential: &C) -> Option<Format> {
    let credential_type = Some(credential.credential_type());
    match query.format.as_str() {
        "mso_mdoc" => {
            let doctype = query.meta.get("doctype_value").and_then(Value::as_str);
            (doctype == credential_type).then_some(Format::Mdoc)
        }
        "dc+sd-jwt" => {
            let vcts = query.meta.get("vct_values").and_then(Value::as_array);
            let listed =
                vcts.is_some_and(|vcts| vcts.iter().any(|v| v.as_str() == credential_type));
            listed.then_some(Format::SdJwtVc)
        }
        _ => None,
    }
}

/// A credential as DCQL's claim selection reads it, with its decimal `credentialId`.
struct Held<'c, C> {
    credential: &'c C,
    id: String,
}

impl<C: MatchCredential> siros_dcql::Credential for Held<'_, C> {
    fn id(&self) -> &str {
        &self.id
    }

    fn format(&self) -> &str {
        self.credential.format().identifier()
    }

    fn claim(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError> {
        self.credential.claim_values(path)
    }

    fn has_cryptographic_holder_binding(&self) -> bool {
        self.credential.key_holding() == KeyHolding::Held
    }
}

/// The candidates of every Credential Query, each with its answer. `R` is why a `zkp_req`
/// candidate answers no option.
pub struct Answered<'r, C, R> {
    credential_sets: Option<&'r [CredentialSetQuery]>,
    queries: Vec<Answers<'r, C, R>>,
}

/// The candidates of one Credential Query.
pub struct Answers<'r, C, R> {
    asked: AskedQuery<'r>,
    candidates: Vec<Candidate<C>>,
    zkp: Option<Box<ZkpQuery>>,
    refusal: Option<QueryRefusal>,
    excluded: Vec<Excluded<C, R>>,
}

/// A credential that answers a Credential Query, and its answer.
pub struct Candidate<C> {
    credential: C,
    answer: Answer,
}

/// A credential that matched a `zkp_req` query and answers none of its options, and why.
pub struct Excluded<C, R> {
    credential: C,
    reason: R,
}

impl<'r, C, R> Answered<'r, C, R> {
    /// The candidates of each Credential Query, in the order of the DCQL query.
    pub fn queries(&self) -> &[Answers<'r, C, R>] {
        &self.queries
    }

    /// The candidates of each Credential Query, with its position.
    pub fn indexed(&self) -> impl Iterator<Item = (QueryIndex, &Answers<'r, C, R>)> {
        self.queries
            .iter()
            .enumerate()
            .map(|(index, answers)| (QueryIndex::at(index), answers))
    }

    /// The candidates of the Credential Query at `index`.
    pub fn answers(&self, index: QueryIndex) -> Option<&Answers<'r, C, R>> {
        self.queries.get(index.value())
    }

    /// The position of the Credential Query `id`.
    pub fn index_of(&self, id: &str) -> Option<QueryIndex> {
        self.indexed()
            .find(|(_, answers)| answers.asked.id == *id)
            .map(|(index, _)| index)
    }

    /// The request's `credential_sets`.
    pub fn credential_sets(&self) -> Option<&'r [CredentialSetQuery]> {
        self.credential_sets
    }
}

impl<'r, C, R> Answers<'r, C, R> {
    /// The Credential Query's `id`.
    pub fn id(&self) -> &QueryId {
        &self.asked.id
    }

    /// The Credential Query.
    pub fn query(&self) -> &'r CredentialQuery {
        self.asked.query
    }

    /// The credentials that answer it, in the order of the wallet's credentials.
    pub fn candidates(&self) -> &[Candidate<C>] {
        &self.candidates
    }

    /// The candidate at `index`.
    pub fn candidate(&self, index: CandidateIndex) -> Option<&Candidate<C>> {
        self.candidates.get(index.value())
    }

    /// The nym_auth query of a `zkp_req` query that has a usable pair.
    pub fn zkp(&self) -> Option<&ZkpQuery> {
        self.zkp.as_deref()
    }

    /// Why the query has no candidate whatever the wallet holds.
    pub fn refusal(&self) -> Option<&QueryRefusal> {
        self.refusal.as_ref()
    }

    /// The credentials that matched a `zkp_req` query and answer none of its options.
    pub fn excluded(&self) -> &[Excluded<C, R>] {
        &self.excluded
    }

    /// The answers of the credentials of `found`, each disclosing its claims.
    fn claims(asked: AskedQuery<'r>, found: Vec<(C, Claims)>) -> Self {
        Self {
            asked,
            candidates: found
                .into_iter()
                .map(|(credential, claims)| Candidate {
                    credential,
                    answer: Answer::Claims(claims),
                })
                .collect(),
            zkp: None,
            refusal: None,
            excluded: Vec::new(),
        }
    }
}

impl<C> Candidate<C> {
    /// The credential.
    pub fn credential(&self) -> &C {
        &self.credential
    }

    /// The answer.
    pub fn answer(&self) -> &Answer {
        &self.answer
    }
}

impl<C, R> Excluded<C, R> {
    /// The credential.
    pub fn credential(&self) -> &C {
        &self.credential
    }

    /// Why it answers no option.
    pub fn reason(&self) -> &R {
        &self.reason
    }
}
