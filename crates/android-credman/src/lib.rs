//! The Android Credential Manager matcher host ABI as types, over
//! `android-credman-sys`, whose `ABI.md` holds the rules.
//!
//! - `None` reaches the host as NULL and hides the element; `Some` of an
//!   empty string shows it blank.
//! - A call above the base level takes its level's token, from
//!   `Host::version`.
//! - The caller keeps two set rules: declare a set id once per invocation,
//!   and give the alternatives of one slot distinct ids.
//! - `Host` exists on `wasm32` only; [`SetSink`] lets a test stand in for it.

#![deny(unsafe_op_in_unsafe_fn)]
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

pub use android_credman_sys::CallingAppInfo;
pub use app::CallingApp;
pub use c8str::{C8Str, C8StrError, C8String};
pub use entry::{
    Field, InlineIssuanceEntry, LegacyEntry, LegacyField, PackageInfo, PaymentDisplay,
    PaymentEntry, StringIdEntry, VerificationDisplay, VerificationLink,
};
#[cfg(target_arch = "wasm32")]
pub use host::Host;
#[cfg(target_arch = "wasm32")]
pub use reader::CredentialReader;
pub use set::{
    AnyEntry, DelegationType, EntryKind, EntrySet, PaymentWithInfo, SetEntry, SetSink, Slot,
    WithDelegation, WithLink, WithMetadataDisplayText,
};
pub use version::{WasmVersion, V2, V3, V4, V5, V6, V7};
