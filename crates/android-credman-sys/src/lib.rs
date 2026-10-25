//! Raw imports of the Android Credential Manager matcher host ABI.
//!
//! Every function the host offers a matcher, under its exact import module
//! and name, with the C types of the interface. [`ABI.md`](../ABI.md) is the
//! contract: for each parameter it says whether NULL is accepted, what a
//! length means and which host version guarantees the function, with the
//! evidence for each claim. The doc comment on each function summarises its
//! row.
//!
//! # Linking
//!
//! A WebAssembly module names its imports, and a host that lacks a named
//! import may refuse to instantiate the module. Rust emits an import only for
//! a function the final binary calls, so a matcher imports exactly what it
//! uses. Each host level beyond the first is behind a Cargo feature
//! (`v2` … `v7`), which keeps a matcher from reaching a level by accident.
//! Calling a function of level N on a host that reports less than N through
//! [`credman::GetWasmVersion`] is outside the contract; the `android-credman`
//! crate makes that check a precondition of the call.
//!
//! # Conventions
//!
//! - Strings are NUL-terminated UTF-8. NULL is accepted only where the
//!   function's documentation says so, and NULL there means "absent", which
//!   the host renders differently from an empty string.
//! - Images are a pointer and a byte length. Where an image is optional,
//!   "absent" is a NULL pointer with length 0.
//! - The host reads every argument before it returns, so the caller may free
//!   its buffers afterwards.
//! - `size_t` and pointers are 32 bits wide on `wasm32`; `long long` is 64.
//!
//! The functions exist only on `wasm32`. [`CallingAppInfo`] exists everywhere
//! so that code reading it can be tested on the build machine.

#![no_std]
#![deny(missing_docs)]

pub use core::ffi::c_char;

/// The caller as the platform verified it, filled by
/// [`credman::GetCallingAppInfo`].
///
/// Two fixed-size byte fields. Each holds a NUL-terminated string when the
/// value is shorter than the field; the layout is part of the ABI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallingAppInfo {
    /// Package name of the calling Android app.
    pub package_name: [u8; 256],
    /// Web origin, when a browser calls on behalf of a page. Empty for a
    /// native app.
    pub origin: [u8; 512],
}

impl CallingAppInfo {
    /// A value with both fields zeroed, for the host to fill.
    pub const ZEROED: CallingAppInfo = CallingAppInfo {
        package_name: [0; 256],
        origin: [0; 512],
    };
}

const _: () = assert!(core::mem::size_of::<CallingAppInfo>() == 256 + 512);
const _: () = assert!(core::mem::align_of::<CallingAppInfo>() == 1);

/// Module `credman`: inputs, the version probe, and the emission functions
/// present on every host.
#[cfg(target_arch = "wasm32")]
pub mod credman {
    use super::{c_char, CallingAppInfo};
    use core::ffi::c_void;

    #[link(wasm_import_module = "credman")]
    extern "C" {
        /// Adds a standalone entry identified by an integer. Superseded by
        /// [`AddStringIdEntry`].
        ///
        /// Every pointer is non-null by the conservative rule: no matcher in
        /// the evidence calls it: `icon` with `icon_len > 0`, `title`, `subtitle`,
        /// `disclaimer`, `warning`.
        pub fn AddEntry(
            cred_id: i64,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// Adds a display field to an entry added by [`AddEntry`].
        /// Superseded by [`AddFieldForStringIdEntry`].
        ///
        /// Both strings non-null by the conservative rule.
        pub fn AddField(
            cred_id: i64,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Adds a standalone entry identified by a string.
        ///
        /// Non-null: `cred_id`, `icon` (with `icon_len > 0`), `title`.
        /// Nullable: `subtitle`, `disclaimer`, `warning`; NULL omits the line.
        /// An empty `disclaimer` or `warning` is shown as a present, blank
        /// label.
        pub fn AddStringIdEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// Adds a display field to the entry [`AddStringIdEntry`] added with
        /// the same `cred_id`.
        ///
        /// Non-null: `cred_id`, `field_display_name`. Nullable:
        /// `field_display_value`; NULL shows the name alone.
        pub fn AddFieldForStringIdEntry(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Copies the request into `buffer`: exactly the number of bytes
        /// [`GetRequestSize`] reported, with no terminator added. `buffer`
        /// must be non-null and hold that many bytes.
        pub fn GetRequestBuffer(buffer: *mut c_void);

        /// Writes the request's length in bytes to `size`, which must be
        /// non-null.
        pub fn GetRequestSize(size: *mut u32);

        /// Copies up to `len` bytes of the registered blob, starting at
        /// `offset`, into `buffer`, and returns how many it copied. The count
        /// can be lower than `len`. `buffer` must be non-null and hold `len`
        /// bytes.
        pub fn ReadCredentialsBuffer(buffer: *mut c_void, offset: usize, len: usize) -> usize;

        /// Writes the registered blob's length in bytes to `size`, which must
        /// be non-null.
        pub fn GetCredentialsSize(size: *mut u32);

        /// Writes the host's ABI level to `version`, which must be non-null.
        ///
        /// Level N guarantees the functions this crate puts at level N and
        /// below. A host that lacks this import predates `credman_v2`.
        pub fn GetWasmVersion(version: *mut u32);

        /// Adds a standalone payment entry.
        ///
        /// Non-null: `cred_id`, `merchant_name`, `payment_method_name`,
        /// `payment_method_icon` (with its length > 0), `transaction_amount`.
        /// Nullable: `payment_method_subtitle`; `bank_icon` and
        /// `payment_provider_icon` as NULL with length 0.
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

        /// Adds an entry that offers to issue a credential the wallet lacks.
        ///
        /// Non-null: `cred_id`. Nullable: `icon` (NULL with length 0),
        /// `title`, `subtitle`. The host shows its own title and icon unless
        /// the registering app is privileged.
        pub fn AddInlineIssuanceEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
        );

        /// Adds a second disclaimer and a link to the entry
        /// [`AddStringIdEntry`] added with the same `cred_id`.
        ///
        /// Every pointer is non-null by the conservative rule: no matcher in
        /// the evidence calls it.
        pub fn SetAdditionalDisclaimerAndUrlForVerificationEntry(
            cred_id: *const c_char,
            secondary_disclaimer: *const c_char,
            url_display_text: *const c_char,
            url_value: *const c_char,
        );

        /// Fills `info`, which must be non-null and point at a whole
        /// [`CallingAppInfo`].
        pub fn GetCallingAppInfo(info: *mut CallingAppInfo);
    }
}

/// Module `credman_v2`: entry sets, from host level 2.
///
/// A set is one option the user selects as a whole. `AddEntrySet` declares
/// its id and its number of positions; each position holds one or more
/// alternative entries, of which the user picks one. Every position from 0 to
/// `set_length - 1` needs at least one entry, a set id is declared once per
/// invocation, and an entry is named by its set, position and `cred_id`.
#[cfg(all(target_arch = "wasm32", feature = "v2"))]
pub mod credman_v2 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v2")]
    extern "C" {
        /// Declares a set with `set_length` positions. `set_id` is non-null
        /// and unique within the invocation; `set_length` is at least 1.
        pub fn AddEntrySet(set_id: *const c_char, set_length: i32);

        /// Adds an alternative at position `set_index` of the set `set_id`.
        ///
        /// Non-null: `cred_id`, `icon` (with `icon_len > 0`; the host drops an
        /// entry without one), `title`, `set_id`. Nullable: `subtitle`,
        /// `disclaimer`, `warning`, `metadata`. An empty `disclaimer` or
        /// `warning` is shown as a present, blank label. `metadata` returns
        /// to the wallet when the user selects the entry.
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

        /// Adds a display field to the entry named by `cred_id`, `set_id` and
        /// `set_index`.
        ///
        /// Non-null: `cred_id`, `field_display_name`, `set_id`. Nullable:
        /// `field_display_value`; NULL shows the name alone.
        pub fn AddFieldToEntrySet(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );

        /// Adds a payment alternative at position `set_index` of the set
        /// `set_id`.
        ///
        /// Pointer rules as [`crate::credman::AddPaymentEntry`], plus nullable
        /// `metadata` and non-null `set_id`.
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

        /// [`AddPaymentEntryToSet`] with a nullable `additional_info`. Host
        /// level 3: it lives in this module but arrived after it.
        #[cfg(feature = "v3")]
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

/// Module `credman_v4`, from host level 4.
#[cfg(all(target_arch = "wasm32", feature = "v4"))]
pub mod credman_v4 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v4")]
    extern "C" {
        /// Declares the display name and icon of the registering app. The
        /// host honours it for system apps only.
        ///
        /// Both are non-null by the conservative rule: no matcher in the
        /// evidence calls it: `package_display_name`, and `package_icon` with
        /// `package_icon_len > 0`.
        pub fn SelfDeclarePackageInfo(
            package_display_name: *const c_char,
            package_icon: *const c_char,
            package_icon_len: usize,
        );
    }
}

/// Module `credman_v5`, from host level 5.
#[cfg(all(target_arch = "wasm32", feature = "v5"))]
pub mod credman_v5 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v5")]
    extern "C" {
        /// Adds a line of metadata text to the entry named by `cred_id`,
        /// `set_id` and `set_index`. Every pointer is non-null.
        pub fn AddMetadataDisplayTextToEntrySet(
            cred_id: *const c_char,
            metadata_display_text: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}

/// Module `credman_v6`, from host level 6.
#[cfg(all(target_arch = "wasm32", feature = "v6"))]
pub mod credman_v6 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v6")]
    extern "C" {
        /// [`crate::credman::SetAdditionalDisclaimerAndUrlForVerificationEntry`]
        /// for the entry named by `cred_id`, `set_id` and `set_index`.
        ///
        /// Every pointer is non-null by the conservative rule. Google's PNV
        /// matcher passes NULL for the three texts when its registry omits
        /// them; no device test confirms the host accepts that.
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

/// Module `credman_v7`, from host level 7.
#[cfg(all(target_arch = "wasm32", feature = "v7"))]
pub mod credman_v7 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v7")]
    extern "C" {
        /// Sets how the entry named by `cred_id`, `set_id` and `set_index` is
        /// fulfilled: 0 by the wallet's own UI, 1 silently through the
        /// wallet's background service. Pointers are non-null.
        pub fn SetDelegationTypeForEntryInSet(
            cred_id: *const c_char,
            delegation_type: i32,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}
