//! A matcher's typed access to the Android Credential Manager host: read the
//! verifier's request, the wallet's registered credentials and the calling
//! app, and fill the credential picker with entries. It wraps
//! `android-credman-sys`, whose `ABI.md` holds the rules and their evidence.
//!
//! - The traits [`V1`] to [`V7`] give each host level's functions as safe
//!   calls. [`Host::credman`] hands out `dyn V1`; `version::<dyn V5>()`
//!   grants a higher level when the host reports it.
//! - [`Host::entry_sets`] sends [`EntrySet`]s from level 2. Each entry
//!   option is sent when the host reaches its level, and the standard
//!   metadata object tells the wallet whether text was left out.
//! - `None` reaches the host as NULL and hides the element; `Some` of an
//!   empty string shows it blank.
//! - The caller keeps two set rules: declare a set id once per invocation,
//!   and give the alternatives of one slot distinct ids.
//! - [`Host`] and the level traits exist on `wasm32` only; [`SetSink`] lets a
//!   test stand in for the host.

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
mod levels;
#[cfg(target_arch = "wasm32")]
mod reader;
mod set;
#[cfg(target_arch = "wasm32")]
mod sets_on_host;
mod text;

pub use app::{CallingApp, CallingAppError};
pub use c8str::{C8Str, C8StrError, C8String, NonZeroChar};
pub use entry::{
    DelegationType, Field, InlineIssuanceEntry, LegacyDisplay, LegacyEntry, LegacyField,
    PackageInfo, PaymentDisplay, PaymentEntry, StringIdEntry, VerificationDisplay,
    VerificationLink,
};
#[cfg(target_arch = "wasm32")]
pub use host::{CredentialsError, Host, HostOptions};
#[cfg(target_arch = "wasm32")]
pub use levels::{EntryKey, Level, V1, V2, V3, V4, V5, V6, V7};
#[cfg(target_arch = "wasm32")]
pub use reader::CredentialReader;
pub use set::{AnyEntry, EntryKind, EntrySet, Payment, SetEntry, SetSink, Slot};
#[cfg(target_arch = "wasm32")]
pub use sets_on_host::EntrySets;
pub use text::{C8StringExt, C8Writer};
