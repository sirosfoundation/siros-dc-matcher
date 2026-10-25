//! Raw imports of the Android Credential Manager matcher host ABI: the
//! functions a matcher calls to read the verifier's request and the wallet's
//! credentials, and to fill the credential picker. One module per host
//! level. [`ABI.md`](../ABI.md) gives each parameter's rule and its evidence.
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
// Links to the wasm32-only functions resolve on wasm32, where rustdoc checks
// them.
#![cfg_attr(not(target_arch = "wasm32"), allow(rustdoc::broken_intra_doc_links))]

pub use core::ffi::c_char;

/// The app that called the Digital Credentials API, as
/// [`credman::GetCallingAppInfo`] writes it. A field shorter than its array
/// ends with a NUL; a full field has none. An empty field holds no value.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallingAppInfo {
    /// The Android package name of the calling app, such as a browser's.
    pub package_name: [u8; 256],
    /// The web page's origin when a browser calls; empty for a native app.
    pub origin: [u8; 512],
}

impl CallingAppInfo {
    /// Both fields empty: the buffer a matcher hands to
    /// [`credman::GetCallingAppInfo`].
    pub const ZEROED: CallingAppInfo = CallingAppInfo {
        package_name: [0; 256],
        origin: [0; 512],
    };
}

const _: () = assert!(core::mem::size_of::<CallingAppInfo>() == 256 + 512);
const _: () = assert!(core::mem::align_of::<CallingAppInfo>() == 1);

/// Functions every host provides: the inputs, the level probe, and the
/// standalone entries a matcher adds on a host below level 2.
#[cfg(target_arch = "wasm32")]
pub mod credman {
    use super::{c_char, CallingAppInfo};
    use core::ffi::c_void;

    #[link(wasm_import_module = "credman")]
    extern "C" {
        /// Adds a standalone entry named by a number. Google's header
        /// deprecates it for [`AddStringIdEntry`], which takes the same
        /// display values, and no known matcher calls it. [`AddField`]
        /// attaches fields by the same `cred_id`.
        ///
        /// Every pointer is required (conservative).
        pub fn AddEntry(
            cred_id: i64,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// Adds a field to the [`AddEntry`] entry with this `cred_id`.
        /// Google's header deprecates it for [`AddFieldForStringIdEntry`],
        /// and no known matcher calls it.
        ///
        /// Both strings are required (conservative).
        pub fn AddField(
            cred_id: i64,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Adds a standalone verification entry to the picker: one credential
        /// the user can select. Google's matcher uses it when the host level
        /// is below 2, where no sets exist.
        ///
        /// - `cred_id` comes back to the wallet when the user selects the
        ///   entry, as androidx's `selectedEntryId`. Fields and the link attach
        ///   by it, so it is unique among the standalone entries of one
        ///   invocation. Required.
        /// - `icon`: the entry's image, 32×32 pixels or rescaled to it
        ///   (androidx). Required, length ≥ 1 (conservative).
        /// - `title`: the entry's title. Required.
        /// - `subtitle`: the line under the title. Nullable.
        /// - `disclaimer`: a note below the entry. Nullable.
        /// - `warning`: a highlighted warning below the entry. Nullable.
        pub fn AddStringIdEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// Adds a field to the [`AddStringIdEntry`] entry with this `cred_id`:
        /// a row naming a value the entry discloses, such as "Age over 21" and
        /// "Yes" (androidx). A matcher adds an entry's fields after the entry.
        ///
        /// `field_display_name` is required. `field_display_value` is
        /// nullable: NULL shows the name alone.
        pub fn AddFieldForStringIdEntry(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Copies the verifier's request into `buffer`: the Digital
        /// Credentials API request as JSON, `{"requests": [{"protocol": …,
        /// "data": …}]}`. A matcher reads it once at start.
        ///
        /// `buffer` holds the [`GetRequestSize`] length. The host writes
        /// exactly that many bytes and no NUL.
        pub fn GetRequestBuffer(buffer: *mut c_void);

        /// Writes the length in bytes of the verifier's request to `size`. A
        /// matcher calls it once at start, then [`GetRequestBuffer`].
        pub fn GetRequestSize(size: *mut u32);

        /// Copies up to `len` bytes of the credential blob, from byte
        /// `offset`, into `buffer`, and returns the count copied. A matcher
        /// reads the whole blob once at start.
        ///
        /// `buffer` holds `len` bytes. The count can be lower than `len` and
        /// is 0 past the end, so a matcher reads until it has the
        /// [`GetCredentialsSize`] length or a read returns 0.
        pub fn ReadCredentialsBuffer(buffer: *mut c_void, offset: usize, len: usize) -> usize;

        /// Writes the length in bytes of the credential blob to `size`. The
        /// blob is the `credentials` bytes the wallet registered with androidx
        /// `RegistryManager`; [`ReadCredentialsBuffer`] reads it.
        pub fn GetCredentialsSize(size: *mut u32);

        /// Writes the host level to `version`. A matcher calls it first and
        /// calls a level-N function only when the level is N or more. It
        /// entered Google's header with level 2, so an older host may lack
        /// it.
        pub fn GetWasmVersion(version: *mut u32);

        /// Adds a standalone payment entry: a payment the user confirms with a
        /// payment credential, such as a card. Google's matcher uses it below
        /// level 2 for a request whose transaction data describes a payment.
        ///
        /// - `cred_id` comes back to the wallet on selection. Required.
        /// - `merchant_name` and `transaction_amount`: the payee and the
        ///   amount as display text, such as `EUR 12.00`. Required: an entry
        ///   without them never shows (Elpaso, on a device).
        /// - `payment_method_name`, `payment_method_subtitle`,
        ///   `payment_method_icon`: the paying credential's title, subtitle
        ///   and image. The name and image are required (conservative); the
        ///   subtitle is nullable.
        /// - `bank_icon`, `payment_provider_icon`: images, nullable. Google's
        ///   matcher passes none; where they show is unconfirmed.
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
        /// On selection the wallet adds the credential and returns it at once
        /// (androidx `InlineIssuanceEntry`). `cred_id` comes back to the wallet
        /// on selection; androidx limits it to 64 characters.
        ///
        /// `icon`, `title` and `subtitle` are nullable. The host shows `icon`
        /// and `title` for system-privileged apps only, and the wallet app's
        /// icon and label otherwise (androidx).
        pub fn AddInlineIssuanceEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
        );

        /// Adds a second disclaimer and a link to the [`AddStringIdEntry`]
        /// entry with this `cred_id`: `url_display_text` is the link's text
        /// and `url_value` its target. Google's phone-number matcher fills the
        /// set form with an aggregator's consent text and policy link. How
        /// the picker draws them is unconfirmed, and no known matcher calls
        /// this form.
        ///
        /// Every pointer is required (conservative).
        pub fn SetAdditionalDisclaimerAndUrlForVerificationEntry(
            cred_id: *const c_char,
            secondary_disclaimer: *const c_char,
            url_display_text: *const c_char,
            url_value: *const c_char,
        );

        /// Fills `info` with the app that called the Digital Credentials API,
        /// as the platform verified it: its package name and, for a browser,
        /// the page's origin. A matcher trusts it over any name or origin
        /// inside the request.
        ///
        /// `info` points to a whole [`CallingAppInfo`].
        pub fn GetCallingAppInfo(info: *mut CallingAppInfo);
    }
}

/// Host level 2: entry sets. The picker offers each set as one option, which
/// the user selects whole, picking one entry at each position. Entries at one
/// position are alternatives.
///
/// Every position from 0 to `set_length - 1` needs an entry; Google's
/// phone-number matcher leaves one empty only at level 7, when every entry of
/// the set is fully delegated. A set id is declared once per invocation. The
/// host names an entry by set id, position and `cred_id`.
#[cfg(target_arch = "wasm32")]
pub mod v2 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v2")]
    extern "C" {
        /// Declares a set with `set_length` positions, numbered from 0. A
        /// matcher declares the set, then adds the entries of every position.
        /// `set_id` comes back to the wallet on selection, as androidx's
        /// `credentialSetId`.
        ///
        /// `set_id` is unique within an invocation: a second declaration of
        /// one id discards everything the matcher added (device).
        /// `set_length` is at least 1.
        pub fn AddEntrySet(set_id: *const c_char, set_length: i32);

        /// Adds a verification entry at position `set_index` of the set
        /// `set_id`: one credential the user can pick for that position.
        ///
        /// - `cred_id` comes back to the wallet on selection, as androidx's
        ///   `credentialId`. It is distinct among the alternatives of one
        ///   position. Fields and the level-5 to level-7 calls attach by it.
        /// - `icon`: the entry's image. The host drops an entry without one
        ///   (device); a 64×64 PNG shows. Required, length ≥ 1.
        /// - `title`: the entry's title. Required.
        /// - `subtitle`: the line under the title. Nullable.
        /// - `disclaimer`: a note below the entry. `warning`: a highlighted
        ///   warning below the entry. Both nullable.
        /// - `metadata`: text the host returns to the wallet with `cred_id` on
        ///   selection. Nullable.
        /// - `set_id` names a set declared by [`AddEntrySet`]; `set_index` is
        ///   below its `set_length`.
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

        /// Adds a field to the entry with this `cred_id` at `set_index` of
        /// `set_id`: a row naming a value the entry discloses, such as "Age
        /// over 21" and "Yes" (androidx). A matcher adds an entry's fields
        /// after the entry.
        ///
        /// `field_display_name` is required. `field_display_value` is
        /// nullable: NULL shows the name alone.
        pub fn AddFieldToEntrySet(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );

        /// Adds a payment entry at position `set_index` of `set_id`, with the
        /// values of [`crate::credman::AddPaymentEntry`] and a nullable
        /// `metadata` the host returns to the wallet on selection. Google's
        /// matcher calls it at level 2 and
        /// [`crate::v3::AddPaymentEntryToSetV2`] from level 3.
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
#[cfg(target_arch = "wasm32")]
pub mod v3 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v2")]
    extern "C" {
        /// [`crate::v2::AddPaymentEntryToSet`] with `additional_info`: more
        /// text about the transaction, which Google's matcher takes from the
        /// request's transaction data. Nullable; how the picker shows it is
        /// unconfirmed.
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
#[cfg(target_arch = "wasm32")]
pub mod v4 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v4")]
    extern "C" {
        /// Declares the wallet app's display name and icon to the host.
        /// Google's header says it works for system apps only. What the
        /// picker does with them is unconfirmed, and no known matcher calls
        /// it.
        ///
        /// Both values are required (conservative).
        pub fn SelfDeclarePackageInfo(
            package_display_name: *const c_char,
            package_icon: *const c_char,
            package_icon_len: usize,
        );
    }
}

/// Host level 5.
#[cfg(target_arch = "wasm32")]
pub mod v5 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v5")]
    extern "C" {
        /// Adds display text to the entry with this `cred_id` at `set_index`
        /// of `set_id`: androidx's `metadataDisplayText`, "the metadata text
        /// to display for this entry". Where it shows is unconfirmed. Google's
        /// matchers send it after the entry's fields, and only when they have
        /// text.
        ///
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
#[cfg(target_arch = "wasm32")]
pub mod v6 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v6")]
    extern "C" {
        /// The set form of
        /// [`crate::credman::SetAdditionalDisclaimerAndUrlForVerificationEntry`]:
        /// a second disclaimer and a link for the entry with this `cred_id` at
        /// `set_index` of `set_id`. Google's phone-number matcher sends it
        /// after the entry and before its fields, with an aggregator's consent
        /// text and policy link.
        ///
        /// Every pointer is required (conservative). Google's matcher passes
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
#[cfg(target_arch = "wasm32")]
pub mod v7 {
    use super::c_char;

    #[link(wasm_import_module = "credman_v7")]
    extern "C" {
        /// Sets how the wallet completes the request when the user picks the
        /// entry with this `cred_id` at `set_index` of `set_id` (androidx
        /// `DelegationType`). Google's phone-number matcher sends it right
        /// after the entry.
        ///
        /// - 0: the host launches the wallet's activity, which handles any
        ///   user interaction.
        /// - 1: the host calls the wallet's background fulfilment service and
        ///   shows a loading indicator meanwhile. A selected set whose entries
        ///   are not all 1 falls back to 0.
        ///
        /// An entry without this call behaves as 0 (unconfirmed: Google's
        /// matcher sends only 1).
        pub fn SetDelegationTypeForEntryInSet(
            cred_id: *const c_char,
            delegation_type: i32,
            set_id: *const c_char,
            set_index: i32,
        );
    }
}
