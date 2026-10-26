//! The identifiers of the wallet state.

use std::fmt;

use serde::Serialize;

/// `credentialId`: the identifier of a credential entry, unique within `S.credentials`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CredentialId(u64);

impl CredentialId {
    /// The identifier `id`, as the wallet state and the credential picker's entries write it.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// The decimal form, as JSON writes the number.
impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// `batchId`: shared by the instances of one issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchId(u64);

impl BatchId {
    pub(crate) fn new(id: u64) -> Self {
        Self(id)
    }
}

/// `instanceId`: the index of a one-time-use instance within its batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstanceId(u64);

impl InstanceId {
    pub(crate) fn new(id: u64) -> Self {
        Self(id)
    }
}

/// The decimal form, as JSON writes the number.
impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// `kid`: the identifier of a key pair of the wallet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

impl KeyId {
    pub(crate) fn new(kid: String) -> Self {
        Self(kid)
    }

    /// The identifier as the wallet state writes it.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `presentationId`: the identifier of a presentation record, drawn at random by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct PresentationId(u64);

impl PresentationId {
    /// The identifier `id`.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}

/// `transactionId`: shared by the presentation records of one response, drawn at random by the
/// host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct TransactionId(u64);

impl TransactionId {
    /// The identifier `id`.
    pub fn new(id: u64) -> Self {
        Self(id)
    }
}
