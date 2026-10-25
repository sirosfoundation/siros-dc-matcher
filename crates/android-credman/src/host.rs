//! Version-aware high-level host facade for Credential Manager matcher output.
//!
//! # Purpose
//! This module exposes a single borrowed-data API over the raw ABI:
//! - `credman()` returns a process-wide `&dyn Credman`.
//! - Version-specific capabilities are discovered through `as_v2()/as_v3()/as_v4()`.
//! - Entry structs carry caller data without per-call allocation.
//!
//! # Typical Flow
//! 1. Build entry structs (`StringIdEntry`, `PaymentEntry`, ...).
//! 2. Call base APIs on `&dyn Credman`.
//! 3. Probe for newer APIs when needed.
//!
//! ```rust
//! use android_credman::{credman, CredentialEntry, CredentialSet, StringIdEntry};
//!
//! let host = credman();
//! let entry = StringIdEntry::new(c"pid-1", c"EU PID");
//! host.add_string_id_entry(&entry);
//!
//! if let Some(v2) = host.as_v2() {
//!     let set =
//!         CredentialSet::new(c"set:pid").add_entry(CredentialEntry::StringId(entry.clone()));
//!     v2.add_entry_set(&set);
//!     v2.add_entry_to_set(&entry, &set.set_id, 0);
//! }
//! ```

use crate::abi;
use crate::{
    CredentialSet, Field, InlineIssuanceEntry, PackageInfo, PaymentEntry, StringIdEntry,
    VerificationEntryUpdate,
};
use core::ffi::CStr;

// === Traits ===

mod sealed {
    pub trait Sealed {}
}

/// Base Credman host contract.
pub trait Credman: sealed::Sealed + Send + Sync {
    /// Host-reported version from `GetWasmVersion`.
    fn wasm_version(&self) -> u32 {
        abi::get_wasm_version()
    }

    /// Adds a standalone identity-style entry.
    fn add_string_id_entry(&self, entry: &StringIdEntry<'_>) {
        abi::add_string_id_entry(entry);
    }

    /// Adds a field to a standalone identity-style entry.
    fn add_field_for_string_id_entry(&self, cred_id: &CStr, field: &Field) {
        abi::add_field_for_string_id_entry(cred_id, field);
    }

    /// Adds a standalone payment entry.
    fn add_payment_entry(&self, entry: &PaymentEntry<'_>) {
        abi::add_payment_entry(entry);
    }

    /// Adds a standalone inline issuance entry.
    fn add_inline_issuance_entry(&self, entry: &InlineIssuanceEntry<'_>) {
        abi::add_inline_issuance_entry(entry);
    }

    /// Updates verification-disclaimer metadata for a previously added entry.
    fn set_additional_disclaimer_and_url_for_verification_entry(
        &self,
        update: &VerificationEntryUpdate<'_>,
    ) {
        abi::set_additional_disclaimer_and_url(update);
    }

    /// Returns `Some` when set APIs are supported (`credman_v2`).
    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        None
    }

    /// Returns `Some` when extended payment set APIs are supported (`v3`).
    fn as_v3(&self) -> Option<&dyn CredmanV3> {
        None
    }

    /// Returns `Some` when system-only package declaration APIs are supported (`v4`).
    fn as_v4(&self) -> Option<&dyn CredmanV4> {
        None
    }
}

/// Version 2 host extension (`credman_v2`).
pub trait CredmanV2: Credman {
    /// Creates a set container.
    fn add_entry_set(&self, set: &CredentialSet<'_>) {
        abi::add_entry_set(set);
    }

    /// Adds an identity-style entry into a set slot.
    fn add_entry_to_set(&self, entry: &StringIdEntry<'_>, set_id: &CStr, set_index: i32) {
        abi::add_entry_to_set(entry, set_id, set_index);
    }

    /// Adds a field to an entry inside a set slot.
    fn add_field_to_entry_set(&self, field: &Field, cred_id: &CStr, set_id: &CStr, set_index: i32) {
        abi::add_field_to_entry_set(field, cred_id, set_id, set_index);
    }

    /// Adds a payment entry into a set slot (v2 payload shape).
    fn add_payment_entry_to_set(&self, entry: &PaymentEntry<'_>, set_id: &CStr, set_index: i32) {
        abi::add_payment_entry_to_set(entry, set_id, set_index);
    }
}

/// Version 3 host extension (`AddPaymentEntryToSetV2`).
pub trait CredmanV3: CredmanV2 {
    /// Adds a payment entry into a set slot (v3 payload with `additional_info`).
    fn add_payment_entry_to_set_v2(&self, entry: &PaymentEntry<'_>, set_id: &CStr, set_index: i32) {
        abi::add_payment_entry_to_set_v2(entry, set_id, set_index);
    }
}

/// Version 4 host extension (`credman_v4`).
pub trait CredmanV4: CredmanV3 {
    /// Declares package info for privileged/system hosts.
    fn self_declare_package_info(&self, info: &PackageInfo<'_>) {
        abi::self_declare_package_info(info);
    }
}

// === Host selection ===

#[derive(Debug, Clone, Copy, Default)]
struct HostCredmanV1;

#[derive(Debug, Clone, Copy, Default)]
struct HostCredmanV2;

#[derive(Debug, Clone, Copy, Default)]
struct HostCredmanV3;

#[derive(Debug, Clone, Copy, Default)]
struct HostCredmanV4;

static HOST_V1: HostCredmanV1 = HostCredmanV1;
static HOST_V2: HostCredmanV2 = HostCredmanV2;
static HOST_V3: HostCredmanV3 = HostCredmanV3;
static HOST_V4: HostCredmanV4 = HostCredmanV4;

/// Returns the process-wide safe Credman handle.
///
/// # Usage
/// 1. Call `credman()` once.
/// 2. Use base methods for v1-safe APIs.
/// 3. Ask for `as_v2` / `as_v3` / `as_v4` before calling newer APIs.
pub fn credman() -> &'static dyn Credman {
    match abi::get_wasm_version() {
        0 | 1 => &HOST_V1,
        2 => &HOST_V2,
        3 => &HOST_V3,
        _ => &HOST_V4,
    }
}

// === Host implementations ===

impl Credman for HostCredmanV1 {}

impl sealed::Sealed for HostCredmanV1 {}

impl Credman for HostCredmanV2 {
    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        Some(self)
    }
}

impl CredmanV2 for HostCredmanV2 {}
impl sealed::Sealed for HostCredmanV2 {}

impl Credman for HostCredmanV3 {
    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        Some(self)
    }

    fn as_v3(&self) -> Option<&dyn CredmanV3> {
        Some(self)
    }
}

impl CredmanV2 for HostCredmanV3 {}
impl CredmanV3 for HostCredmanV3 {}
impl sealed::Sealed for HostCredmanV3 {}

impl Credman for HostCredmanV4 {
    fn as_v2(&self) -> Option<&dyn CredmanV2> {
        Some(self)
    }

    fn as_v3(&self) -> Option<&dyn CredmanV3> {
        Some(self)
    }

    fn as_v4(&self) -> Option<&dyn CredmanV4> {
        Some(self)
    }
}

impl CredmanV2 for HostCredmanV4 {}
impl CredmanV3 for HostCredmanV4 {}
impl CredmanV4 for HostCredmanV4 {}
impl sealed::Sealed for HostCredmanV4 {}
