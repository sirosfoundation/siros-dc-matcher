//! Why text is not a wallet state the core reads. Each error has a stable code.

use std::fmt;

/// Why text is not the `S` of a WalletStateContainer (privatedata 3.1, Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletStateError {
    /// The text is not a JSON object.
    Malformed,
    /// `schemaVersion` is neither 3 nor 4. An absent `schemaVersion` means version 1.
    UnsupportedSchemaVersion,
    /// `credentials` is absent or not an array.
    Credentials,
    /// An entry of `credentials` is not an object.
    CredentialEntry,
    /// A member of Section 6.0 is absent from a credential entry or has the wrong type. The
    /// number members are non-negative integers of 64 bits; the others are strings.
    CredentialMember(&'static str),
    /// Two credential entries share a `credentialId`.
    RepeatedCredentialId,
    /// `metadata` is not an array of objects, each with a non-empty string `type` and a
    /// `value`.
    Metadata,
    /// `keypairs` is absent or not an array.
    Keypairs,
    /// `presentations` is absent or not an array of objects with the six members of
    /// `new_presentation`: `presentationId` and `transactionId` non-negative integers of 64
    /// bits, `usedCredentialIds` an array of them, `presentationTimestampSeconds` a second of
    /// the years 0000 to 9999, and the strings `data` and `audience`.
    Presentations,
}

impl WalletStateError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "state_malformed",
            Self::UnsupportedSchemaVersion => "schema_version_unsupported",
            Self::Credentials => "credentials_malformed",
            Self::CredentialEntry => "credential_entry_malformed",
            Self::CredentialMember(_) => "credential_member_malformed",
            Self::RepeatedCredentialId => "credential_id_repeated",
            Self::Metadata => "metadata_malformed",
            Self::Keypairs => "keypairs_malformed",
            Self::Presentations => "presentations_malformed",
        }
    }
}

impl fmt::Display for WalletStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialMember(member) => write!(f, "{}: {member}", self.code()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for WalletStateError {}
