//! Matching (A1, A2): the candidates of each Credential Query of a request, one instance per
//! batch (C5).

mod zkp;

use serde_json::Value;
use siros_codec::date::Date;
use siros_credential::{least_used, ClaimPointer, Format};
use siros_dcql::eval::select_claims;
use siros_dcql::{CredentialQuery, DcqlQuery, PathComponent, PathError};
use siros_wallet_state::PresentationRecord;
use siros_zkp_req::{failure_code, ErrorCode, Match};
use siros_zkp_req_nym_auth::catalogue::{BBS_SCHEMA_ID, MDOC_DOCTYPE};
use siros_zkp_req_nym_auth::policy::RequestRefusal;
use siros_zkp_req_nym_auth::system::NymAuthSystem;

use crate::credential::MatchCredential;

pub use zkp::{ProofChoice, ZkpQuery};

/// The request as the matching reads it: its DCQL query, the query as sent, and the Verifier
/// metadata.
#[derive(Debug, Clone, Copy)]
pub struct Asked<'r> {
    query: &'r DcqlQuery,
    raw: &'r Value,
    client_metadata: Option<&'r Value>,
}

impl<'r> Asked<'r> {
    /// The request of `query`, which the Verifier sent as `raw`, with its `client_metadata`.
    pub fn new(query: &'r DcqlQuery, raw: &'r Value, client_metadata: Option<&'r Value>) -> Self {
        Self {
            query,
            raw,
            client_metadata,
        }
    }

    /// The DCQL query.
    pub fn query(&self) -> &'r DcqlQuery {
        self.query
    }

    /// The Credential Query `id` as sent.
    fn raw_credential(&self, id: &str) -> Option<&'r Value> {
        self.raw
            .get("credentials")?
            .as_array()?
            .iter()
            .find(|c| c.get("id").and_then(Value::as_str) == Some(id))
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
    holder_binding: bool,
}

impl Claims {
    /// The claims path pointers, in the order of the claims query; `[namespace, element]` for an
    /// mdoc.
    pub fn pointers(&self) -> &[ClaimPointer] {
        &self.pointers
    }

    /// Whether the query requires cryptographic holder binding (OpenID4VP 1.0, Section 6.1).
    pub fn holder_binding(&self) -> bool {
        self.holder_binding
    }
}

/// The credentials that can answer each Credential Query, before the `zkp_req` credential
/// tests.
pub struct Matching<'r, C> {
    asked: Asked<'r>,
    queries: Vec<(&'r CredentialQuery, Outcome<C>)>,
}

enum Outcome<C> {
    Claims(Vec<(C, Claims)>),
    Proof {
        zkp: Box<ZkpQuery>,
        credentials: Vec<C>,
    },
    Failed(ErrorCode),
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
    /// are selected by DCQL (OpenID4VP 1.0, Section 6.4.1). `policy` says whether the request
    /// meets the nym_auth policy; a nym_auth query of a request that does not is invalid.
    pub fn new(
        asked: Asked<'r>,
        credentials: &[C],
        records: &[PresentationRecord],
        systems: &[NymAuthSystem],
        date: Date,
        policy: Result<(), RequestRefusal>,
    ) -> Self {
        let instances = least_used(credentials, records);
        let queries = asked
            .query
            .credentials
            .iter()
            .map(|query| {
                let outcome = match query.format.as_str() {
                    "zkp_req" => match ZkpQuery::read(
                        asked.raw_credential(&query.id),
                        asked.client_metadata,
                        policy,
                        systems,
                        date,
                    ) {
                        Ok(zkp) => Outcome::Proof {
                            credentials: instances
                                .iter()
                                .filter(|c| zkp.proves_over(**c))
                                .map(|c| (*c).clone())
                                .collect(),
                            zkp: Box::new(zkp),
                        },
                        Err(code) => Outcome::Failed(code),
                    },
                    _ => Outcome::Claims(
                        instances
                            .iter()
                            .filter_map(|c| claims(query, *c).map(|claims| ((*c).clone(), claims)))
                            .collect(),
                    ),
                };
                (query, outcome)
            })
            .collect();
        Self { asked, queries }
    }

    /// The answers of every query: `choose` picks the [`ProofChoice`] of each `zkp_req`
    /// candidate by its index in [`ZkpQuery::choices`], or drops the candidate with `None`. The
    /// wallet applies the credential tests there (A2); the picker, which cannot, picks the
    /// first.
    pub fn answer(self, mut choose: impl FnMut(&C, &ZkpQuery) -> Option<usize>) -> Answered<'r, C> {
        let queries = self
            .queries
            .into_iter()
            .map(|(query, outcome)| match outcome {
                Outcome::Claims(found) => Answers {
                    query,
                    candidates: found
                        .into_iter()
                        .map(|(credential, claims)| Candidate {
                            credential,
                            answer: Answer::Claims(claims),
                        })
                        .collect(),
                    zkp: None,
                    failure: None,
                },
                Outcome::Proof { zkp, credentials } => Answers {
                    query,
                    candidates: credentials
                        .into_iter()
                        .filter_map(|credential| {
                            let choice = zkp.choices().get(choose(&credential, &zkp)?)?.clone();
                            Some(Candidate {
                                credential,
                                answer: Answer::Proof(choice),
                            })
                        })
                        .collect(),
                    zkp: Some(zkp),
                    failure: None,
                },
                Outcome::Failed(code) => Answers {
                    query,
                    candidates: Vec::new(),
                    zkp: None,
                    failure: Some(code),
                },
            })
            .collect();
        Answered {
            asked: self.asked,
            queries,
        }
    }
}

/// The claims `query` selects in `credential`, when the credential matches the query's format
/// and `meta` (A1) and holds every claim the query asks for.
fn claims<C: MatchCredential>(query: &CredentialQuery, credential: &C) -> Option<Claims> {
    let text = |name: &str| query.meta.get(name).and_then(Value::as_str);
    let format = match query.format.as_str() {
        "mso_mdoc" if text("doctype_value") == Some(credential.credential_type()) => Format::Mdoc,
        "dc+sd-jwt" => {
            let listed = query
                .meta
                .get("vct_values")
                .and_then(Value::as_array)
                .is_some_and(|vcts| {
                    vcts.iter()
                        .any(|v| v.as_str() == Some(credential.credential_type()))
                });
            if !listed {
                return None;
            }
            Format::SdJwtVc
        }
        _ => return None,
    };
    let needs_key = format == Format::Mdoc || query.require_cryptographic_holder_binding;
    let nym_auth = [MDOC_DOCTYPE, BBS_SCHEMA_ID].contains(&credential.credential_type());
    if credential.format() != format || nym_auth || (needs_key && !credential.holds_key()) {
        return None;
    }
    let held = Held {
        credential,
        id: credential.entry().credential_id().to_string(),
    };
    let selected = select_claims(query, &held)?;
    let pointers = selected
        .into_iter()
        .map(|claim| ClaimPointer::parse(claim.path).ok())
        .collect::<Option<Vec<_>>>()?;
    Some(Claims {
        pointers,
        holder_binding: query.require_cryptographic_holder_binding,
    })
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
        self.credential.holds_key()
    }
}

/// The candidates of every Credential Query, each with its answer.
pub struct Answered<'r, C> {
    asked: Asked<'r>,
    queries: Vec<Answers<'r, C>>,
}

/// The candidates of one Credential Query.
pub struct Answers<'r, C> {
    query: &'r CredentialQuery,
    candidates: Vec<Candidate<C>>,
    zkp: Option<Box<ZkpQuery>>,
    failure: Option<ErrorCode>,
}

/// A credential that answers a Credential Query, and its answer.
pub struct Candidate<C> {
    credential: C,
    answer: Answer,
}

impl<'r, C> Answered<'r, C> {
    /// The request.
    pub fn asked(&self) -> Asked<'r> {
        self.asked
    }

    /// The candidates of each Credential Query, in the order of the DCQL query.
    pub fn queries(&self) -> &[Answers<'r, C>] {
        &self.queries
    }

    /// The error a request without an offer gets (`zkp_req.md`, Section 5): the first of
    /// `invalid_request`, `vp_formats_not_supported` and `access_denied` a query gives.
    pub fn failure(&self) -> ErrorCode {
        let outcomes: Vec<Match<(), (), ()>> = self
            .queries
            .iter()
            .map(|answers| match answers.failure {
                Some(ErrorCode::InvalidRequest) => Match::Invalid(()),
                Some(ErrorCode::VpFormatsNotSupported) => Match::Unsupported(Vec::new()),
                Some(ErrorCode::AccessDenied) | None => Match::Rejected(Vec::new()),
            })
            .collect();
        failure_code(&outcomes).unwrap_or(ErrorCode::AccessDenied)
    }
}

impl<'r, C> Answers<'r, C> {
    /// The Credential Query.
    pub fn query(&self) -> &'r CredentialQuery {
        self.query
    }

    /// The credentials that answer it, in the order of the wallet's credentials.
    pub fn candidates(&self) -> &[Candidate<C>] {
        &self.candidates
    }

    /// The nym_auth query of a `zkp_req` query that has a usable pair.
    pub fn zkp(&self) -> Option<&ZkpQuery> {
        self.zkp.as_deref()
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
