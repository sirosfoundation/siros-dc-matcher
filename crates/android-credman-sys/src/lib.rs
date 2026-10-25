//! Raw imports of the Android Credential Manager matcher host ABI, one module
//! and Cargo feature per host level. [`ABI.md`](../ABI.md) gives each
//! parameter's rule and its evidence.
//!
//! - Call a level-N function only when `GetWasmVersion` reports N or more.
//! - Strings are NUL-terminated UTF-8. A nullable string is hidden when NULL
//!   and shown blank when empty.
//! - An optional image is absent as NULL with length 0.
//! - Out-pointers are required.
//! - The host reads every argument during the call.
//!
//! The functions exist on `wasm32` only.

#![no_std]

pub use core::ffi::c_char;

/// Filled by `credman::GetCallingAppInfo`. A field is NUL-terminated when its
/// value is shorter than the field.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallingAppInfo {
    pub package_name: [u8; 256],
    /// The page's origin when a browser calls; empty for a native app.
    pub origin: [u8; 512],
}

impl CallingAppInfo {
    pub const ZEROED: CallingAppInfo = CallingAppInfo {
        package_name: [0; 256],
        origin: [0; 512],
    };
}

const _: () = assert!(core::mem::size_of::<CallingAppInfo>() == 256 + 512);
const _: () = assert!(core::mem::align_of::<CallingAppInfo>() == 1);

/// Every host level: inputs, the version probe and standalone entries.
#[cfg(target_arch = "wasm32")]
pub mod credman {
    use super::{c_char, CallingAppInfo};
    use core::ffi::c_void;

    #[link(wasm_import_module = "credman")]
    extern "C" {
        /// Superseded by [`AddStringIdEntry`]. Every pointer is required
        /// (conservative).
        pub fn AddEntry(
            cred_id: i64,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// Superseded by [`AddFieldForStringIdEntry`]. Both strings are required
        /// (conservative).
        pub fn AddField(
            cred_id: i64,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Required: `cred_id`, `icon` (length ≥ 1), `title`. Nullable:
        /// `subtitle`, `disclaimer`, `warning`.
        pub fn AddStringIdEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// Adds a field to the [`AddStringIdEntry`] entry with this `cred_id`.
        /// Nullable: `field_display_value`.
        pub fn AddFieldForStringIdEntry(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Writes exactly [`GetRequestSize`] bytes, unterminated.
        pub fn GetRequestBuffer(buffer: *mut c_void);

        pub fn GetRequestSize(size: *mut u32);

        /// Returns the bytes copied, which can be fewer than `len`.
        pub fn ReadCredentialsBuffer(buffer: *mut c_void, offset: usize, len: usize) -> usize;

        pub fn GetCredentialsSize(size: *mut u32);

        /// The host level. A host without this import predates `credman_v2`.
        pub fn GetWasmVersion(version: *mut u32);

        /// Required: `cred_id`, `merchant_name`, `payment_method_name`,
        /// `payment_method_icon` (length ≥ 1), `transaction_amount`. Nullable:
        /// `payment_method_subtitle`, `bank_icon`, `payment_provider_icon`.
        pub fn AddPaymentEntry(
            cred_id: *const c_char,
            merchant_name: *const c_char,
            payment_method_name: *const c_char,
            payment_method_subtitle: *const c_char,
            payment_method_icon: *const c_char,
            payment_method_icon_len: usize,
            transaction_amount: *const c_char,
            bank_icon: *const c_char,
            bank_icon_len: usize,
            payment_provider_icon: *const c_char,
            payment_provider_icon_len: usize,
        );

        /// Offers to issue a credential the wallet lacks. Nullable: `icon`,
        /// `title`, `subtitle`. The host shows `icon` and `title` for privileged
        /// apps only.
        pub fn AddInlineIssuanceEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
        );

        /// Adds a second disclaimer and a link to the [`AddStringIdEntry`]
        /// entry with this `cred_id`. Every pointer is required (conservative).
        pub fn SetAdditionalDisclaimerAndUrlForVerificationEntry(
            cred_id: *const c_char,
            secondary_disclaimer: *const c_char,
            url_display_text: *const c_char,
            url_value: *const c_char,
        );

        pub fn GetCallingAppInfo(info: *mut CallingAppInfo);
    }
}

/// Host level 2: entry sets. Every position from 0 to `set_length - 1` needs
/// an entry, a set id is declared once per invocation, and the host names an
/// entry by set, position and `cred_id`.
#[cfg(all(target_arch = "wasm32", feature = "v2"))]
pub mod credman_v2 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v2")]
    extern "C" {
        /// `set_length` is at least 1.
        pub fn AddEntrySet(set_id: *const c_char, set_length: i32);

        /// Adds an alternative at position `set_index`. Required: `cred_id`,
        /// `icon` (length ≥ 1; the host drops an entry without one), `title`,
        /// `set_id`. Nullable: `subtitle`, `disclaimer`, `warning`, `metadata`.
        /// `metadata` returns to the wallet on selection.
        pub fn AddEntryToSet(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
            metadata: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );

        /// Nullable: `field_display_value`.
        pub fn AddFieldToEntrySet(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );

        /// The rules of [`crate::credman::AddPaymentEntry`]; `metadata` is
        /// nullable.
        pub fn AddPaymentEntryToSet(
            cred_id: *const c_char,
            merchant_name: *const c_char,
            payment_method_name: *const c_char,
            payment_method_subtitle: *const c_char,
            payment_method_icon: *const c_char,
            payment_method_icon_len: usize,
            transaction_amount: *const c_char,
            bank_icon: *const c_char,
            bank_icon_len: usize,
            payment_provider_icon: *const c_char,
            payment_provider_icon_len: usize,
            metadata: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}

/// Host level 3. Its one function is imported from `credman_v2`: Google's
/// header declares it there.
#[cfg(all(target_arch = "wasm32", feature = "v3"))]
pub mod credman_v3 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v2")]
    extern "C" {
        /// [`crate::credman_v2::AddPaymentEntryToSet`] with a nullable
        /// `additional_info`.
        pub fn AddPaymentEntryToSetV2(
            cred_id: *const c_char,
            merchant_name: *const c_char,
            payment_method_name: *const c_char,
            payment_method_subtitle: *const c_char,
            payment_method_icon: *const c_char,
            payment_method_icon_len: usize,
            transaction_amount: *const c_char,
            bank_icon: *const c_char,
            bank_icon_len: usize,
            payment_provider_icon: *const c_char,
            payment_provider_icon_len: usize,
            additional_info: *const c_char,
            metadata: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}

/// Host level 4.
#[cfg(all(target_arch = "wasm32", feature = "v4"))]
pub mod credman_v4 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v4")]
    extern "C" {
        /// Honoured for system apps only. Both pointers are required
        /// (conservative).
        pub fn SelfDeclarePackageInfo(
            package_display_name: *const c_char,
            package_icon: *const c_char,
            package_icon_len: usize,
        );
    }
}

/// Host level 5.
#[cfg(all(target_arch = "wasm32", feature = "v5"))]
pub mod credman_v5 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v5")]
    extern "C" {
        /// Every pointer is required.
        pub fn AddMetadataDisplayTextToEntrySet(
            cred_id: *const c_char,
            metadata_display_text: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}

/// Host level 6.
#[cfg(all(target_arch = "wasm32", feature = "v6"))]
pub mod credman_v6 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v6")]
    extern "C" {
        /// Every pointer is required (conservative). Google's PNV matcher passes
        /// NULL texts, untested on a device.
        pub fn SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(
            cred_id: *const c_char,
            secondary_disclaimer: *const c_char,
            url_display_text: *const c_char,
            url_value: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}

/// Host level 7.
#[cfg(all(target_arch = "wasm32", feature = "v7"))]
pub mod credman_v7 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v7")]
    extern "C" {
        /// `delegation_type`: 0, the wallet's UI handles selection; 1, the
        /// wallet's background service fulfils it.
        pub fn SetDelegationTypeForEntryInSet(
            cred_id: *const c_char,
            delegation_type: i32,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}
