//! The rules of the nym_auth catalogue a query breaks, with what breaks them.

use std::fmt;

use siros_zkp_req::{ItemIndex, ReqSetIndex};

use super::{Prf, VerifierContextError};

/// What breaks the rule of a parameter or a `meta` member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamFault {
    /// It is absent.
    Absent,
    /// It has another JSON type than the catalogue gives it.
    WrongType,
    /// Its value is none the catalogue defines, or breaks the syntax the catalogue gives it.
    Value,
}

/// What breaks the rule of `verifier_context`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextFault {
    /// `account-recovery-ssc` has no `verifier_context`.
    Absent,
    /// Another configuration has a `verifier_context`.
    Forbidden,
    /// It is not a string.
    WrongType,
    /// The string is no `verifier_context`.
    Invalid(VerifierContextError),
}

/// A rule of the catalogue that a query breaks, with what breaks it. Each makes the query
/// invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatalogueRule {
    /// `meta` names the `bbs_cd` form without a string `schema_id_value`.
    SchemaIdInvalid(ParamFault),
    /// `require_cryptographic_holder_binding` is `false`.
    HolderBindingWaived,
    /// `fn_id` is not in the catalogue.
    FunctionUnknown {
        /// The item's index.
        item: ItemIndex,
    },
    /// A parameter the function does not define.
    ParamUnknown {
        /// The item's index.
        item: ItemIndex,
    },
    /// `pseudonym` without `return`.
    PseudonymReturnMissing {
        /// The item's index.
        item: ItemIndex,
    },
    /// `config` is absent, not a string or not a configuration.
    ConfigInvalid {
        /// The item's index.
        item: ItemIndex,
        /// What breaks the rule.
        fault: ParamFault,
    },
    /// `ver` is absent, not an unsigned integer, or not 1.
    VerInvalid {
        /// The item's index.
        item: ItemIndex,
        /// What breaks the rule.
        fault: ParamFault,
    },
    /// `prf` is absent, not a string or not a PRF.
    PrfInvalid {
        /// The item's index.
        item: ItemIndex,
        /// What breaks the rule.
        fault: ParamFault,
    },
    /// `prf` names a PRF the catalogue does not define for the source format and
    /// configuration.
    PrfUndefined {
        /// The item's index.
        item: ItemIndex,
        /// The PRF.
        prf: Prf,
    },
    /// `verifier_context` is absent where required, present where forbidden, not a string, or
    /// not 1 to 64 bytes.
    VerifierContextInvalid {
        /// The item's index.
        item: ItemIndex,
        /// What breaks the rule.
        fault: ContextFault,
    },
    /// `range` is absent, not a string, or breaks the syntax.
    RangeSyntax {
        /// The item's index.
        item: ItemIndex,
        /// What breaks the rule.
        fault: ParamFault,
    },
    /// `range` is `A-B` with A greater than B.
    RangeInverted {
        /// The item's index.
        item: ItemIndex,
    },
    /// An option holds more than one `pseudonym`.
    PseudonymRepeated {
        /// The option's index in `_req_sets`, `None` without them.
        option: Option<ReqSetIndex>,
    },
    /// An option holds more than one `age_check`.
    AgeCheckRepeated {
        /// The option's index in `_req_sets`, `None` without them.
        option: Option<ReqSetIndex>,
    },
}

impl CatalogueRule {
    /// A stable identifier of the rule, shared with the conformance vectors.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SchemaIdInvalid(_) => "schema_id_invalid",
            Self::HolderBindingWaived => "holder_binding_waived",
            Self::FunctionUnknown { .. } => "function_unknown",
            Self::ParamUnknown { .. } => "param_unknown",
            Self::PseudonymReturnMissing { .. } => "pseudonym_return_missing",
            Self::ConfigInvalid { .. } => "config_invalid",
            Self::VerInvalid { .. } => "ver_invalid",
            Self::PrfInvalid { .. } | Self::PrfUndefined { .. } => "prf_invalid",
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
