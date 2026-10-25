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

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

extern crate alloc;

mod app;
mod entry;
#[cfg(target_arch = "wasm32")]
mod host;
#[cfg(all(target_arch = "wasm32", feature = "std"))]
mod reader;
mod set;
#[cfg(all(target_arch = "wasm32", feature = "v2"))]
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
#[cfg(all(target_arch = "wasm32", feature = "std"))]
pub use reader::CredentialReader;
#[cfg(feature = "v7")]
pub use set::DelegationType;
#[cfg(feature = "v3")]
pub use set::PaymentWithInfo;
pub use set::{AnyEntry, EntryKind, EntrySet, SetEntry, SetSink, Slot};
pub use version::WasmVersion;
#[cfg(feature = "v2")]
pub use version::V2;
#[cfg(feature = "v3")]
pub use version::V3;
#[cfg(feature = "v4")]
pub use version::V4;
#[cfg(feature = "v5")]
pub use version::V5;
#[cfg(feature = "v6")]
pub use version::V6;
#[cfg(feature = "v7")]
pub use version::V7;
