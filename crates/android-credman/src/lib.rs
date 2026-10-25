//! Typed, version-gated access to the Android Credential Manager matcher
//! host ABI.
//!
//! The raw imports are in `android-credman-sys`; its `ABI.md` is the
//! contract, with the evidence for each rule. This crate states the
//! contract in its types:
//!
//! - **Nullability.** A string the host needs is a `&C8Str`, valid UTF-8 and
//!   NUL-terminated at once; one it accepts as absent is an
//!   `Option<&C8Str>`, sent as NULL. A required image is a `&[u8]`; an
//!   optional one is an `Option<&[u8]>`, sent as NULL with length 0.
//! - **Version gating.** [`Host::connect`] reads `GetWasmVersion` once.
//!   [`WasmVersion`] hands out one token per level (`V2` … `V7`), and every
//!   call above the base level takes its token: the level-2 token emits
//!   entry sets, the level-4 token declares package info, and the tokens of
//!   levels 3, 5, 6 and 7 unlock the matching parts of a [`SetEntry`]. A
//!   Cargo feature per level (`v2` … `v7`) keeps the imports of a level out
//!   of a matcher that does not enable it.
//! - **Set shape.** An [`EntrySet`] has at least one slot and every slot at
//!   least one entry; positions and the declared length follow from the
//!   slots, and fields and decorations belong to their entry.
//!
//! The host exists only on `wasm32`, where [`Host`] and the emitters are
//! defined. The data types compile everywhere, and [`SetSink`] lets a test
//! stand in for the host.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
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
