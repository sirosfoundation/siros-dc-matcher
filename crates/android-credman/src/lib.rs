//! A matcher's typed access to the Android Credential Manager host: read the
//! verifier's request, the wallet's registered credentials and the calling
//! app, and fill the credential picker with entries. It wraps
//! `android-credman-sys`, whose `ABI.md` holds the rules and their evidence.
//!
//! - `None` reaches the host as NULL and hides the element; `Some` of an
//!   empty string shows it blank.
//! - A call above the base level takes its level's token, from
//!   [`Host::version`]. [`Host::connect_with`] checks the level itself for
//!   the package info it declares.
//! - The caller keeps two set rules: declare a set id once per invocation,
//!   and give the alternatives of one slot distinct ids.
//! - [`Host`] exists on `wasm32` only; [`SetSink`] lets a test stand in for
//!   it.

#![deny(unsafe_op_in_unsafe_fn)]
// Links to the wasm32-only host API resolve on wasm32, where rustdoc checks
// them.
#![cfg_attr(not(target_arch = "wasm32"), allow(rustdoc::broken_intra_doc_links))]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod app;
mod entry;
#[cfg(target_arch = "wasm32")]
mod host;
#[cfg(target_arch = "wasm32")]
mod reader;
mod set;
#[cfg(target_arch = "wasm32")]
mod sets_on_host;
mod version;

pub use app::{CallingApp, CallingAppError};
pub use c8str::{C8Str, C8StrError, C8String};
pub use entry::{
    Field, InlineIssuanceEntry, LegacyEntry, LegacyField, PaymentDisplay, PaymentEntry,
    StringIdEntry, VerificationDisplay, VerificationLink,
};
#[cfg(target_arch = "wasm32")]
pub use host::{CredentialsError, Host, HostOptions, PackageInfo};
#[cfg(target_arch = "wasm32")]
pub use reader::CredentialReader;
pub use set::{
    AnyEntry, DelegationType, EntryKind, EntrySet, PaymentWithInfo, SetEntry, SetSink, Slot,
    WithDelegation, WithLink, WithMetadataDisplayText,
};
pub use version::{WasmVersion, V2, V3, V5, V6, V7};
