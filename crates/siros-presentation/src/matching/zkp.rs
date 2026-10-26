//! `zkp_req` matching (A2): the options in the Verifier's order, each with the first available
//! system that forms a usable pair for it.

use serde_json::Value;
use siros_codec::date::Date;
use siros_zkp_req::{CredentialType, ErrorCode, QueryOption, ZkpFormats, ZkpReqQuery};
use siros_zkp_req_nym_auth::catalogue::NymAuthQuery;
use siros_zkp_req_nym_auth::pair::UsablePair;
use siros_zkp_req_nym_auth::policy::RequestRefusal;
use siros_zkp_req_nym_auth::system::NymAuthSystem;

use crate::credential::MatchCredential;
use siros_credential::Format;

/// A nym_auth query of a request that meets the nym_auth policy, with the options that have a
/// usable pair at the proof date.
#[derive(Debug, Clone)]
pub struct ZkpQuery {
    query: NymAuthQuery,
    formats: ZkpFormats,
    date: Date,
    choices: Vec<ProofChoice>,
}

/// An option of a nym_auth query, and the system and proof backend that form its usable pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofChoice {
    option: usize,
    req_set: Option<usize>,
    system: NymAuthSystem,
    backend: String,
}

impl ProofChoice {
    /// The option's index among the query's options.
    pub fn option(&self) -> usize {
        self.option
    }

    /// The option's index in `_req_sets`; `None` for a query without them.
    pub fn req_set(&self) -> Option<usize> {
        self.req_set
    }

    /// The system.
    pub fn system(&self) -> NymAuthSystem {
        self.system
    }

    /// The proof backend.
    pub fn backend(&self) -> &str {
        &self.backend
    }
}

impl ZkpQuery {
    /// The nym_auth query of the Credential Query `raw`, at the proof date `date`.
    ///
    /// The query follows `zkp_req` and the catalogue, `client_metadata` lists the Verifier's
    /// systems and proof backends (`zkp_req.md`, Section 1.2), and `policy` holds. Each option,
    /// in the Verifier's order, takes the first of `systems` that forms a usable pair for it.
    ///
    /// # Errors
    ///
    /// The `zkp_req.md`, Section 5 code: `invalid_request` for a query, a metadata or a request
    /// that breaks a rule, `vp_formats_not_supported` for a query of another credential type or
    /// without an option with a usable pair.
    pub(crate) fn read(
        raw: Option<&Value>,
        client_metadata: Option<&Value>,
        policy: Result<(), RequestRefusal>,
        systems: &[NymAuthSystem],
        date: Date,
    ) -> Result<Self, ErrorCode> {
        let invalid = ErrorCode::InvalidRequest;
        let parsed = ZkpReqQuery::parse(raw.ok_or(invalid)?).map_err(|_| invalid)?;
        let formats = ZkpFormats::from_client_metadata(client_metadata.ok_or(invalid)?)
            .map_err(|_| invalid)?;
        let query = NymAuthQuery::from_query(parsed)
            .map_err(|_| invalid)?
            .nym_auth()
            .ok_or(ErrorCode::VpFormatsNotSupported)?;
        policy.map_err(|_| invalid)?;
        let choices: Vec<ProofChoice> = query
            .options()
            .enumerate()
            .filter_map(|(index, option)| {
                systems.iter().find_map(|&system| {
                    let pair = option.pair(&formats, system, date).ok()?;
                    Some(ProofChoice {
                        option: index,
                        req_set: option.option().req_set,
                        system,
                        backend: pair.backend().to_owned(),
                    })
                })
            })
            .collect();
        if choices.is_empty() {
            return Err(ErrorCode::VpFormatsNotSupported);
        }
        Ok(Self {
            query,
            formats,
            date,
            choices,
        })
    }

    /// The nym_auth query.
    pub fn query(&self) -> &NymAuthQuery {
        &self.query
    }

    /// The options with a usable pair, in the Verifier's order, each with its pair.
    pub fn choices(&self) -> &[ProofChoice] {
        &self.choices
    }

    /// The option of `choice`; `None` for a choice of another query.
    pub fn option(&self, choice: &ProofChoice) -> Option<&QueryOption> {
        self.query.query().options.get(choice.option)
    }

    /// The usable pair of `choice` again, at the proof date of the matching. `None` for a
    /// choice of another query.
    pub fn pair(&self, choice: &ProofChoice) -> Option<UsablePair<'_>> {
        let pair = self
            .query
            .options()
            .nth(choice.option)?
            .pair(&self.formats, choice.system, self.date)
            .ok()?;
        (pair.backend() == choice.backend).then_some(pair)
    }

    /// Whether the query's systems prove over `credential`: an mdoc of the query's `docType`
    /// whose key the wallet holds, the catalogue requiring holder binding.
    pub(crate) fn proves_over<C: MatchCredential>(&self, credential: &C) -> bool {
        let doctype = match &self.query.query().credential_type {
            CredentialType::MsoMdoc { doctype } => doctype,
            _ => return false,
        };
        credential.format() == Format::Mdoc
            && credential.credential_type() == doctype
            && credential.holds_key()
    }
}
