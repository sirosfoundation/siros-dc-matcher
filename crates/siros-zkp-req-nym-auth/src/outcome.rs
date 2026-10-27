//! What a nym_auth query, credential or proof can fail on, as typed values with the codes of
//! the specs.

use std::fmt;

use siros_zkp_req::{ItemIndex, ReqSetIndex, RequestRule};

use crate::catalogue::CatalogueRule;

/// A rule a request breaks: `zkp_req`'s or the catalogue's (`invalid_request`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidRequest {
    /// A rule of `zkp_req`.
    Protocol(RequestRule),
    /// A rule of the nym_auth catalogue.
    Catalogue(CatalogueRule),
}

impl InvalidRequest {
    /// The rule's stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Protocol(rule) => rule.code(),
            Self::Catalogue(rule) => rule.code(),
        }
    }
}

impl fmt::Display for InvalidRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for InvalidRequest {}

impl From<RequestRule> for InvalidRequest {
    fn from(rule: RequestRule) -> Self {
        Self::Protocol(rule)
    }
}

impl From<CatalogueRule> for InvalidRequest {
    fn from(rule: CatalogueRule) -> Self {
        Self::Catalogue(rule)
    }
}

/// An item's own failure (system rulebooks, Section 9, `ItemError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemCode {
    /// The birth date lies outside `[E, C]` (`age_check`).
    AgeOutOfRange,
    /// `SHA-256(secret_seed)` differs from `ssc` (`pseudonym`).
    SeedMismatch,
}

impl ItemCode {
    /// The rulebook's code.
    pub fn code(self) -> &'static str {
        match self {
            Self::AgeOutOfRange => "age_out_of_range",
            Self::SeedMismatch => "seed_mismatch",
        }
    }
}

/// A failed check of the credential (system rulebooks, Section 9, `CredentialError`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialCode {
    /// The proof time lies outside `[validFrom, validUntil)`.
    Validity,
    /// `issuerAuth` fails under the `x5chain` key.
    IssuerSignature,
    /// The device signature fails under the MSO's device key.
    DeviceBinding,
    /// The credential lies outside the form the system reads.
    CredentialForm,
}

impl CredentialCode {
    /// The rulebook's code.
    pub fn code(self) -> &'static str {
        match self {
            Self::Validity => "validity",
            Self::IssuerSignature => "issuer_signature",
            Self::DeviceBinding => "device_binding",
            Self::CredentialForm => "credential_form",
        }
    }
}

/// Why a credential cannot answer an option. For the User only: the Verifier receives
/// `access_denied` without a description.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ZkpError {
    /// An item fails.
    Item {
        /// The option's index in `_req_sets`, `None` without them.
        option: Option<ReqSetIndex>,
        /// The item's `_req` index.
        item: ItemIndex,
        /// The failure.
        code: ItemCode,
    },
    /// A check of the credential fails.
    Credential(CredentialCode),
}

impl ZkpError {
    /// The rulebook's code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Item { code, .. } => code.code(),
            Self::Credential(code) => code.code(),
        }
    }
}

impl fmt::Display for ZkpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
