//! The nym_auth function catalogue: the `pseudonym` and `age_check` items, and the rules a
//! nym_auth Credential Query follows (nym_auth rulebook, "Presentation" and "Function
//! catalogue").

use std::fmt;

use serde_json::{Map, Value};
use siros_zkp_req::{CredentialType, QueryOption, ReturnHandle, ZkpReqQuery};

use crate::age::{AgeRange, RangeError};

/// The `docType` and namespace of the ISO/IEC 18013-5 form.
pub const MDOC_DOCTYPE: &str = "eu.europa.ec.eudi.nym_auth.1";
/// The schema identifier of the `bbs_cd` form.
pub const BBS_SCHEMA_ID: &str = "eu.europa.ec.eudi.nym_auth.bbs.1";

/// The form of the attestation a query asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Form {
    /// `mso_mdoc`, `doctype_value` [`MDOC_DOCTYPE`].
    Mdoc,
    /// `bbs_cd`, `schema_id_value` [`BBS_SCHEMA_ID`].
    BbsCd,
}

/// A `pseudonym` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Config {
    /// `known-offender-matching-ssc`.
    KnownOffenderMatchingSsc,
    /// `known-offender-matching-psc`.
    KnownOffenderMatchingPsc,
    /// `account-recovery-ssc`, with its `verifier_context`: 1 to 64 bytes of UTF-8.
    AccountRecoverySsc {
        /// `verifier_context`, as sent.
        verifier_context: String,
    },
    /// `user-managed-pseudonym-xsite-ssc`.
    UserManagedPseudonymXsiteSsc,
}

impl Config {
    /// The configuration's identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KnownOffenderMatchingSsc => "known-offender-matching-ssc",
            Self::KnownOffenderMatchingPsc => "known-offender-matching-psc",
            Self::AccountRecoverySsc { .. } => "account-recovery-ssc",
            Self::UserManagedPseudonymXsiteSsc => "user-managed-pseudonym-xsite-ssc",
        }
    }
}

/// The pseudorandom function of a `pseudonym`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prf {
    /// `sha-256`.
    Sha256,
    /// `hashdh-bls12381g1`.
    HashdhBls12381G1,
}

impl Prf {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "sha-256" => Some(Self::Sha256),
            "hashdh-bls12381g1" => Some(Self::HashdhBls12381G1),
            _ => None,
        }
    }

    /// Whether the catalogue defines this PRF for `form` and `config`.
    fn defined_for(self, form: Form, config: &Config) -> bool {
        match (self, form) {
            (Self::Sha256, Form::Mdoc) => true,
            (Self::HashdhBls12381G1, Form::BbsCd) => *config == Config::KnownOffenderMatchingSsc,
            _ => false,
        }
    }
}

/// A `pseudonym` item. Its `ver` is 1, the only version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pseudonym {
    /// `config`, with `verifier_context` where the configuration takes one.
    pub config: Config,
    /// `prf`.
    pub prf: Prf,
}

/// An `age_check` item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgeCheck {
    /// `range`.
    pub range: AgeRange,
}

/// A function of the catalogue, with its parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Function {
    /// `pseudonym`. Its result is a `bstr`.
    Pseudonym(Pseudonym),
    /// `age_check`. It has no result.
    AgeCheck(AgeCheck),
}

/// Whether the function `fn_id` has a result (`zkp_req`, Section 3): `pseudonym` has a `bstr`,
/// `age_check` none.
pub fn has_result(fn_id: &str) -> bool {
    fn_id == "pseudonym"
}

/// One `_req` item, typed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Item {
    /// The function and its parameters.
    pub function: Function,
    /// `return`.
    pub ret: Option<ReturnHandle>,
}

/// A rule of the catalogue that a query breaks. Each makes the query invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatalogueRule {
    /// `meta` names the `bbs_cd` form without a string `schema_id_value`.
    SchemaIdInvalid,
    /// `require_cryptographic_holder_binding` is `false`.
    HolderBindingWaived,
    /// `fn_id` is not in the catalogue.
    FunctionUnknown {
        /// The item's index.
        item: usize,
    },
    /// A parameter the function does not define.
    ParamUnknown {
        /// The item's index.
        item: usize,
    },
    /// `pseudonym` without `return`.
    PseudonymReturnMissing {
        /// The item's index.
        item: usize,
    },
    /// `config` is missing, not a string or not a configuration.
    ConfigInvalid {
        /// The item's index.
        item: usize,
    },
    /// `ver` is missing or not 1.
    VerInvalid {
        /// The item's index.
        item: usize,
    },
    /// `prf` is missing, not a string, or undefined for the source format and configuration.
    PrfInvalid {
        /// The item's index.
        item: usize,
    },
    /// `verifier_context` is missing where required, present where forbidden, not a string, or
    /// not 1 to 64 bytes.
    VerifierContextInvalid {
        /// The item's index.
        item: usize,
    },
    /// `range` is missing or not a string, or breaks the syntax.
    RangeSyntax {
        /// The item's index.
        item: usize,
    },
    /// `range` is `A-B` with A greater than B.
    RangeInverted {
        /// The item's index.
        item: usize,
    },
    /// An option holds more than one `pseudonym`.
    PseudonymRepeated {
        /// The option's index in `_req_sets`, `None` without them.
        option: Option<usize>,
    },
    /// An option holds more than one `age_check`.
    AgeCheckRepeated {
        /// The option's index in `_req_sets`, `None` without them.
        option: Option<usize>,
    },
}

impl CatalogueRule {
    /// A stable identifier of the rule, shared with the conformance vectors.
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaIdInvalid => "schema_id_invalid",
            Self::HolderBindingWaived => "holder_binding_waived",
            Self::FunctionUnknown { .. } => "function_unknown",
            Self::ParamUnknown { .. } => "param_unknown",
            Self::PseudonymReturnMissing { .. } => "pseudonym_return_missing",
            Self::ConfigInvalid { .. } => "config_invalid",
            Self::VerInvalid { .. } => "ver_invalid",
            Self::PrfInvalid { .. } => "prf_invalid",
            Self::VerifierContextInvalid { .. } => "verifier_context_invalid",
            Self::RangeSyntax { .. } => "range_syntax",
            Self::RangeInverted { .. } => "range_inverted",
            Self::PseudonymRepeated { .. } => "pseudonym_repeated",
            Self::AgeCheckRepeated { .. } => "age_check_repeated",
        }
    }
}

impl fmt::Display for CatalogueRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for CatalogueRule {}

/// A nym_auth Credential Query, validated against the catalogue.
#[derive(Debug, Clone, PartialEq)]
pub struct NymAuthQuery {
    /// The query as `zkp_req` reads it.
    pub query: ZkpReqQuery,
    /// The attestation form it asks for.
    pub form: Form,
    /// `_req`, typed, in order.
    pub items: Vec<Item>,
}

impl NymAuthQuery {
    /// Validates `query` against the catalogue. `None` when `meta` asks for another credential
    /// type: this catalogue does not apply to it.
    ///
    /// # Errors
    ///
    /// [`CatalogueRule`]: the first rule the query breaks.
    pub fn from_query(query: ZkpReqQuery) -> Result<Option<Self>, CatalogueRule> {
        let Some(form) = form_of(&query.credential_type)? else {
            return Ok(None);
        };
        if !query.require_holder_binding {
            return Err(CatalogueRule::HolderBindingWaived);
        }
        let items = query
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| read_item(index, item, form))
            .collect::<Result<Vec<_>, _>>()?;
        for option in &query.options {
            check_option(option, &items)?;
        }
        Ok(Some(Self { query, form, items }))
    }

    /// The typed items of `option`, with their `_req` indexes.
    pub fn option_items<'a>(
        &'a self,
        option: &'a QueryOption,
    ) -> impl Iterator<Item = (usize, &'a Item)> + 'a {
        option
            .items
            .iter()
            .filter_map(move |&index| self.items.get(index).map(|item| (index, item)))
    }
}

fn form_of(credential_type: &CredentialType) -> Result<Option<Form>, CatalogueRule> {
    match credential_type {
        CredentialType::MsoMdoc { doctype } => Ok((doctype == MDOC_DOCTYPE).then_some(Form::Mdoc)),
        CredentialType::Profiled {
            source_format,
            meta,
        } if source_format == "bbs_cd" => match meta.get("schema_id_value") {
            Some(Value::String(schema)) => Ok((schema == BBS_SCHEMA_ID).then_some(Form::BbsCd)),
            _ => Err(CatalogueRule::SchemaIdInvalid),
        },
        _ => Ok(None),
    }
}

fn check_option(option: &QueryOption, items: &[Item]) -> Result<(), CatalogueRule> {
    let functions = option.items.iter().filter_map(|&i| items.get(i));
    let (mut pseudonyms, mut ages) = (0, 0);
    for item in functions {
        match item.function {
            Function::Pseudonym(_) => pseudonyms += 1,
            Function::AgeCheck(_) => ages += 1,
        }
    }
    if pseudonyms > 1 {
        return Err(CatalogueRule::PseudonymRepeated {
            option: option.req_set,
        });
    }
    if ages > 1 {
        return Err(CatalogueRule::AgeCheckRepeated {
            option: option.req_set,
        });
    }
    Ok(())
}

fn read_item(
    index: usize,
    item: &siros_zkp_req::ReqItem,
    form: Form,
) -> Result<Item, CatalogueRule> {
    let function = match item.fn_id.as_str() {
        "pseudonym" => {
            if item.ret.is_none() {
                return Err(CatalogueRule::PseudonymReturnMissing { item: index });
            }
            Function::Pseudonym(read_pseudonym(index, &item.params, form)?)
        }
        "age_check" => Function::AgeCheck(read_age_check(index, &item.params)?),
        _ => return Err(CatalogueRule::FunctionUnknown { item: index }),
    };
    Ok(Item {
        function,
        ret: item.ret.clone(),
    })
}

fn only_params(
    index: usize,
    params: &Map<String, Value>,
    known: &[&str],
) -> Result<(), CatalogueRule> {
    if params.keys().any(|k| !known.contains(&k.as_str())) {
        return Err(CatalogueRule::ParamUnknown { item: index });
    }
    Ok(())
}

fn read_pseudonym(
    index: usize,
    params: &Map<String, Value>,
    form: Form,
) -> Result<Pseudonym, CatalogueRule> {
    only_params(index, params, &["config", "ver", "prf", "verifier_context"])?;
    let name = params
        .get("config")
        .and_then(Value::as_str)
        .ok_or(CatalogueRule::ConfigInvalid { item: index })?;
    let context = params.get("verifier_context");
    let config = read_config(index, name, context)?;
    if params.get("ver").and_then(Value::as_u64) != Some(1) {
        return Err(CatalogueRule::VerInvalid { item: index });
    }
    let prf = params
        .get("prf")
        .and_then(Value::as_str)
        .and_then(Prf::parse)
        .filter(|prf| prf.defined_for(form, &config))
        .ok_or(CatalogueRule::PrfInvalid { item: index })?;
    Ok(Pseudonym { config, prf })
}

/// The configuration named `name`. `verifier_context` is required for account recovery and
/// forbidden elsewhere.
fn read_config(index: usize, name: &str, context: Option<&Value>) -> Result<Config, CatalogueRule> {
    let context_invalid = CatalogueRule::VerifierContextInvalid { item: index };
    let config = match name {
        "known-offender-matching-ssc" => Config::KnownOffenderMatchingSsc,
        "known-offender-matching-psc" => Config::KnownOffenderMatchingPsc,
        "user-managed-pseudonym-xsite-ssc" => Config::UserManagedPseudonymXsiteSsc,
        "account-recovery-ssc" => {
            return match context {
                Some(Value::String(c)) if (1..=64).contains(&c.len()) => {
                    Ok(Config::AccountRecoverySsc {
                        verifier_context: c.clone(),
                    })
                }
                _ => Err(context_invalid),
            };
        }
        _ => return Err(CatalogueRule::ConfigInvalid { item: index }),
    };
    match context {
        None => Ok(config),
        Some(_) => Err(context_invalid),
    }
}

fn read_age_check(index: usize, params: &Map<String, Value>) -> Result<AgeCheck, CatalogueRule> {
    only_params(index, params, &["range"])?;
    let text = params
        .get("range")
        .and_then(Value::as_str)
        .ok_or(CatalogueRule::RangeSyntax { item: index })?;
    let range = AgeRange::parse(text).map_err(|e| match e {
        RangeError::Syntax => CatalogueRule::RangeSyntax { item: index },
        RangeError::Inverted => CatalogueRule::RangeInverted { item: index },
    })?;
    Ok(AgeCheck { range })
}
