//! The decrypted wallet state `S` of the SIROS private data container (privatedata 3.1,
//! Section 6), as the wallet core reads it.
//!
//! | Requirement | API |
//! | --- | --- |
//! | W1: `schemaVersion` 3 or 4, absent meaning 1 | [`WalletState::parse`] |
//! | W2: unique 64-bit `credentialId`s, the eight members of Section 6.0, `metadata` verbatim | [`CredentialEntry`], [`MetadataEntry`] |
//! | W3: credentials, presentations and key identifiers | [`WalletState::credentials`], [`WalletState::presentations`], [`WalletState::key_ids`] |
//! | W4: the record the host appends as a `new_presentation` event | [`PresentationRecord`] |
//!
//! The host supplies `S` with its events folded in. Types that hold a credential, a
//! presentation or a `metadata` value implement no `Debug`: those hold claim values and
//! delivered secrets (R-G6).

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod entry;
mod error;
mod ids;
mod presentation;
mod state;

pub use entry::{CredentialData, CredentialEntry, MetadataEntry, MetadataType, MetadataValue};
pub use error::{
    ArrayFault, FoundVersion, Member, MetadataFault, PresentationsFault, TypeFault,
    WalletStateError,
};
pub use ids::{
    BatchId, ConfigurationId, CredentialId, EmptyIdentifier, FormatIdentifier, InstanceId,
    IssuerIdentifier, KeyId, PresentationId, TransactionId,
};
pub use presentation::PresentationRecord;
pub use state::WalletState;
