#![doc = include_str!("../README.md")]

use std::ffi::{c_char, c_void};

#[cfg(not(target_arch = "wasm32"))]
pub mod test_shim;

/// Represents information about the application requesting the credential.
///
/// This struct is populated by the Android system (`GetCallingAppInfo`) to let your Matcher
/// decide if it trusts the caller.
///
/// # Security Note
/// You should use this to implement "Allow Lists". For example, only allowing
/// a high-value ID card to be presented to specific, trusted `package_names` or `origins`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CallingAppInfo {
    /// The Android Package Name of the caller (e.g., `com.amazon.mShop.android.shopping`).
    ///
    /// * **Usage:** Populated when the request comes from an installed Android App.
    /// * **Format:** Null-terminated C-string if length < 256.
    pub package_name: [u8; 256],

    /// The Web Origin of the caller (e.g., `https://www.paypal.com`).
    ///
    /// * **Usage:** Populated when the request comes from a Browser (Chrome/System WebView).
    /// * **Format:** Null-terminated C-string if length < 512.
    pub origin: [u8; 512],
}

// -------------------------------------------------------------------------
// Module: credman
// Contains the core API functions exposed by the Android Credential Manager
// sandbox environment to the WASM Matcher.
// -------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
pub mod credman {
    use super::*;

    #[link(wasm_import_module = "credman")]
    unsafe extern "C" {
        /// **DEPRECATED**: Adds a standard credential entry using a numeric ID.
        ///
        /// * **Status:** Legacy. Do not use for new implementations.
        /// * **Replacement:** Use [`AddStringIdEntry`] instead.
        ///
        /// # Parameters
        /// * `cred_id`: Legacy numeric callback identifier.
        /// * `icon`: Optional icon bytes pointer.
        /// * `icon_len`: Icon byte length.
        /// * `title`: Primary row title.
        /// * `subtitle`: Optional secondary row text.
        /// * `disclaimer`: Optional legal/disclaimer text.
        /// * `warning`: Optional warning text.
        #[link_name = "AddEntry"]
        pub fn AddEntry(
            cred_id: i64,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// **DEPRECATED**: Adds a field to a numeric ID entry.
        ///
        /// * **Status:** Legacy.
        /// * **Replacement:** Use [`AddFieldForStringIdEntry`] instead.
        ///
        /// # Parameters
        /// * `cred_id`: Legacy numeric callback identifier.
        /// * `field_display_name`: Field label.
        /// * `field_display_value`: Field value.
        #[link_name = "AddField"]
        pub fn AddField(
            cred_id: i64,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Adds a standard credential entry to the Android system selector.
        ///
        /// This is the primary function to display an Identity Credential (mDL, Employee ID, etc.).
        ///
        /// # Parameters
        /// * `cred_id`: **REQUIRED**. A unique string ID. This is returned to your app if the user selects this entry.
        /// * `icon`: *Optional*. Pointer to PNG/WEBP image data. Pass `null` if no icon.
        /// * `icon_len`: Length of the icon buffer. Pass `0` if `icon` is `null`.
        /// * `title`: **REQUIRED**. The main large text (e.g., "California Driver's License").
        /// * `subtitle`: *Optional*. Secondary text below the title (e.g., "Exp: 12/2028").
        /// * `disclaimer`: *Optional*. Small legal text in the footer.
        /// * `warning`: *Optional*. Text displayed in a warning color (e.g., "Expired").
        pub fn AddStringIdEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
            disclaimer: *const c_char,
            warning: *const c_char,
        );

        /// Adds a key-value detail field to a specific credential entry.
        ///
        /// These fields are usually displayed in an "accordion" or detail view when the
        /// user inspects the card.
        ///
        /// # Parameters
        /// * `cred_id`: **REQUIRED**. Must match the `cred_id` of a previously added entry.
        /// * `field_display_name`: **REQUIRED**. The label (e.g., "Member Since").
        /// * `field_display_value`: Usually a value (e.g., "2024"). Some hosts also accept `null`.
        ///
        /// # Note on Ordering
        /// Fields are typically displayed in the order they are added.
        pub fn AddFieldForStringIdEntry(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
        );

        /// Copies the Verifier's JSON request into the provided buffer.
        ///
        /// Use this to read the OID4VP or mDoc request data.
        /// * **Pre-requisite:** Call [`GetRequestSize`] first to allocate a sufficiently large buffer.
        pub fn GetRequestBuffer(buffer: *mut c_void);

        /// Gets the size (in bytes) of the Verifier's JSON request.
        pub fn GetRequestSize(size: *mut u32);

        /// Reads a chunk of the registered credential metadata.
        ///
        /// This function supports **offset-based reading**, which is critical for parsing
        /// large credential stores (e.g., multiple SD-JWTs) without exhausting the WASM memory limit.
        ///
        /// # Returns
        /// The number of bytes actually read.
        pub fn ReadCredentialsBuffer(buffer: *mut c_void, offset: usize, len: usize) -> usize;

        /// Gets the total size (in bytes) of the registered metadata blob.
        pub fn GetCredentialsSize(size: *mut u32);

        /// Gets the API version of the host Credential Manager.
        ///
        /// Use this to detect if `credman_v2` features (like Sets) are available.
        pub fn GetWasmVersion(version: *mut u32);

        /// Populates the [`CallingAppInfo`] struct with details about the Verifier.
        pub fn GetCallingAppInfo(info: *mut CallingAppInfo);

        /// Adds a high-fidelity "Payment" style entry (SCA).
        ///
        /// Used for **Strong Customer Authentication**. This entry type is rendered with
        /// special UI emphasis on the `amount` and `merchant` to prevent transaction fraud.
        ///
        /// # Parameters
        /// * `cred_id`: **REQUIRED**. Unique ID returned to your app.
        /// * `merchant_name`: **REQUIRED**. The merchant name (e.g., "Starbucks").
        ///   *If missing, the entry may be rejected by the OS.*
        /// * `payment_method_name`: *Optional*. e.g., "Visa Infinite". Defaults to generic if null.
        /// * `payment_method_subtitle`: *Optional*. e.g., "**** 1234".
        /// * `payment_method_icon`: *Optional*. The card network logo.
        /// * `payment_method_icon_len`: Length of `payment_method_icon`.
        /// * `transaction_amount`: **REQUIRED**. The formatted amount (e.g., "$12.50").
        ///   *Must match the `transaction_data` in the request JSON.*
        /// * `bank_icon`: *Optional*. The issuer bank's logo.
        /// * `bank_icon_len`: Length of `bank_icon`.
        /// * `payment_provider_icon`: *Optional*. Additional provider branding.
        /// * `payment_provider_icon_len`: Length of `payment_provider_icon`.
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

        /// Adds an entry that triggers an "Inline Issuance" flow.
        ///
        /// Use this when you don't have the requested credential, but you want to offer
        /// the user a chance to issue/provision it right now.
        pub fn AddInlineIssuanceEntry(
            cred_id: *const c_char,
            icon: *const c_char,
            icon_len: usize,
            title: *const c_char,
            subtitle: *const c_char,
        );

        /// Updates an entry to include specific regulatory disclosures and a verification URL.
        ///
        /// Often used for "Verified by [Issuer]" links or region-specific legal requirements.
        pub fn SetAdditionalDisclaimerAndUrlForVerificationEntry(
            cred_id: *const c_char,
            secondary_disclaimer: *const c_char,
            url_display_text: *const c_char,
            url_value: *const c_char,
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(
    unsafe_op_in_unsafe_fn,
    clippy::missing_safety_doc,
    clippy::too_many_arguments
)]
pub mod credman {
    use super::*;
    use crate::test_shim;

    #[allow(non_snake_case)]
    pub unsafe fn AddEntry(
        cred_id: i64,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        subtitle: *const c_char,
        disclaimer: *const c_char,
        warning: *const c_char,
    ) {
        test_shim::record(test_shim::DisplayEvent::AddEntry {
            cred_id,
            icon: test_shim::bytes_from_ptr(icon, icon_len),
            title: test_shim::c_str_to_string(title),
            subtitle: test_shim::c_str_to_string(subtitle),
            disclaimer: test_shim::c_str_to_string(disclaimer),
            warning: test_shim::c_str_to_string(warning),
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddField(
        cred_id: i64,
        field_display_name: *const c_char,
        field_display_value: *const c_char,
    ) {
        test_shim::record(test_shim::DisplayEvent::AddField {
            cred_id,
            display_name: test_shim::c_str_to_string(field_display_name),
            display_value: test_shim::c_str_to_string(field_display_value),
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddStringIdEntry(
        cred_id: *const c_char,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        subtitle: *const c_char,
        disclaimer: *const c_char,
        warning: *const c_char,
    ) {
        let cred_id = test_shim::c_str_to_string(cred_id).unwrap_or_default();
        let title = test_shim::c_str_to_string(title).unwrap_or_default();
        test_shim::record(test_shim::DisplayEvent::AddStringIdEntry {
            cred_id,
            icon: test_shim::bytes_from_ptr(icon, icon_len),
            title,
            subtitle: test_shim::c_str_to_string(subtitle),
            disclaimer: test_shim::c_str_to_string(disclaimer),
            warning: test_shim::c_str_to_string(warning),
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddFieldForStringIdEntry(
        cred_id: *const c_char,
        field_display_name: *const c_char,
        field_display_value: *const c_char,
    ) {
        let cred_id = test_shim::c_str_to_string(cred_id).unwrap_or_default();
        let display_name = test_shim::c_str_to_string(field_display_name).unwrap_or_default();
        test_shim::record(test_shim::DisplayEvent::AddFieldForStringIdEntry {
            cred_id,
            display_name,
            display_value: test_shim::c_str_to_string(field_display_value),
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn GetRequestBuffer(buffer: *mut c_void) {
        test_shim::write_request(buffer);
    }

    #[allow(non_snake_case)]
    pub unsafe fn GetRequestSize(size: *mut u32) {
        if let Some(size) = size.as_mut() {
            *size = test_shim::request_len();
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn ReadCredentialsBuffer(buffer: *mut c_void, offset: usize, len: usize) -> usize {
        test_shim::read_credentials(buffer, offset, len)
    }

    #[allow(non_snake_case)]
    pub unsafe fn GetCredentialsSize(size: *mut u32) {
        if let Some(size) = size.as_mut() {
            *size = test_shim::credentials_len();
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn GetWasmVersion(version: *mut u32) {
        if let Some(version) = version.as_mut() {
            *version = 0;
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn GetCallingAppInfo(info: *mut CallingAppInfo) {
        if let Some(info) = info.as_mut() {
            *info = CallingAppInfo {
                package_name: [0; 256],
                origin: [0; 512],
            };
        }
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddPaymentEntry(
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
    ) {
        test_shim::record(test_shim::DisplayEvent::AddPaymentEntry {
            cred_id: test_shim::c_str_to_string(cred_id).unwrap_or_default(),
            merchant_name: test_shim::c_str_to_string(merchant_name).unwrap_or_default(),
            payment_method_name: test_shim::c_str_to_string(payment_method_name),
            payment_method_subtitle: test_shim::c_str_to_string(payment_method_subtitle),
            payment_method_icon: test_shim::bytes_from_ptr(
                payment_method_icon,
                payment_method_icon_len,
            ),
            transaction_amount: test_shim::c_str_to_string(transaction_amount).unwrap_or_default(),
            bank_icon: test_shim::bytes_from_ptr(bank_icon, bank_icon_len),
            payment_provider_icon: test_shim::bytes_from_ptr(
                payment_provider_icon,
                payment_provider_icon_len,
            ),
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddInlineIssuanceEntry(
        cred_id: *const c_char,
        icon: *const c_char,
        icon_len: usize,
        title: *const c_char,
        subtitle: *const c_char,
    ) {
        test_shim::record(test_shim::DisplayEvent::AddInlineIssuanceEntry {
            cred_id: test_shim::c_str_to_string(cred_id).unwrap_or_default(),
            icon: test_shim::bytes_from_ptr(icon, icon_len),
            title: test_shim::c_str_to_string(title).unwrap_or_default(),
            subtitle: test_shim::c_str_to_string(subtitle),
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn SetAdditionalDisclaimerAndUrlForVerificationEntry(
        cred_id: *const c_char,
        secondary_disclaimer: *const c_char,
        url_display_text: *const c_char,
        url_value: *const c_char,
    ) {
        test_shim::record(
            test_shim::DisplayEvent::SetAdditionalDisclaimerAndUrlForVerificationEntry {
                cred_id: test_shim::c_str_to_string(cred_id).unwrap_or_default(),
                secondary_disclaimer: test_shim::c_str_to_string(secondary_disclaimer),
                url_display_text: test_shim::c_str_to_string(url_display_text),
                url_value: test_shim::c_str_to_string(url_value),
            },
        );
    }
}

// -------------------------------------------------------------------------
// Module: credman_v2
// Set (grouping) logic for credentials — represents an OR-selection.
//
// This module corresponds to Android 15+ features that allow grouping
// multiple credentials (e.g., multiple SD-JWTs) into a single parent
// item that expands. A Set is rendered as a parent row; selecting it
// reveals child credentials. Only one child may be selected — it is an
// OR-select across children.
//
// # Mixing Sets and Standalone Entries
// You can mix calls to `credman::AddStringIdEntry` and `credman_v2::AddEntrySet`.
// Each call creates a separate top-level entry in the Android Credential Manager
// selector. If multiple Sets are provided, each will appear as its own visual
// group.
//
// Constraints:
// - You MUST create a Set with the expected child count before adding children.
// - The `set_length` must equal the number of children you add.
// - `set_index` is 0-based and MUST be within [0, set_length).
// - Sets should be non-empty; empty sets are invalid.
// -------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
pub mod credman_v2 {
    use super::*;

    #[link(wasm_import_module = "credman_v2")]
    unsafe extern "C" {
        /// Creates a new "Entry Set" (a visual group/folder of credentials).
        ///
        /// # Parameters
        /// * `set_id`: **REQUIRED**. A unique string ID for this group.
        /// * `set_length`: **REQUIRED**. The number of set slots (not alternatives).
        pub fn AddEntrySet(set_id: *const c_char, set_length: i32);

        /// Adds a standard credential to a specific "Entry Set".
        ///
        /// # Parameters
        /// * `cred_id`: **REQUIRED**. Callback identifier for this credential entry.
        /// * `icon`: Optional icon bytes pointer.
        /// * `icon_len`: Icon byte length.
        /// * `title`: **REQUIRED**. Primary row title.
        /// * `subtitle`: Optional secondary row text.
        /// * `disclaimer`: Optional legal/disclaimer text.
        /// * `warning`: Optional warning text.
        /// * `metadata`: Optional opaque JSON/string payload returned on selection.
        /// * `set_id`: **REQUIRED**. Must match a `set_id` created via `AddEntrySet`.
        /// * `set_index`: **REQUIRED**. The 0-based index (order) of this item in the set.
        ///
        /// # Relationship to OR-selection
        /// Each call to `AddEntryToSet` for a given `set_index` adds an alternative for
        /// that position in the set.
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

        /// Adds a field (key-value) to a credential inside a set.
        ///
        /// # Parameters
        /// * `cred_id`: Entry identifier already emitted for this set slot.
        /// * `field_display_name`: Field label shown to the user.
        /// * `field_display_value`: Field value; some hosts accept `null`.
        /// * `set_id`: Set identifier created by `AddEntrySet`.
        /// * `set_index`: 0-based slot index for the target entry.
        pub fn AddFieldToEntrySet(
            cred_id: *const c_char,
            field_display_name: *const c_char,
            field_display_value: *const c_char,
            set_id: *const c_char,
            set_index: i32,
        );

        /// Adds a Payment/SCA credential to an "Entry Set".
        ///
        /// # Parameters
        /// * `cred_id`: **REQUIRED**. Callback identifier for this payment entry.
        /// * `merchant_name`: **REQUIRED**. Must match the transaction request.
        /// * `payment_method_name`: Optional payment method title.
        /// * `payment_method_subtitle`: Optional payment method subtitle.
        /// * `payment_method_icon`: Optional icon bytes pointer.
        /// * `payment_method_icon_len`: Icon byte length.
        /// * `transaction_amount`: **REQUIRED**. Must match the transaction request.
        /// * `bank_icon`: Optional bank icon bytes pointer.
        /// * `bank_icon_len`: Bank icon byte length.
        /// * `payment_provider_icon`: Optional provider icon bytes pointer.
        /// * `payment_provider_icon_len`: Provider icon byte length.
        /// * `metadata`: Optional opaque JSON/string payload returned on selection.
        /// * `set_id`: Set identifier created by `AddEntrySet`.
        /// * `set_index`: 0-based slot index for the target entry.
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

        /// Adds a Payment/SCA credential to an "Entry Set" with `additional_info`.
        ///
        /// This function is used by newer host versions (v3+) and corresponds to
        /// `AddPaymentEntryToSetV2` in the C ABI.
        ///
        /// # Parameters
        /// Same as [`AddPaymentEntryToSet`] plus:
        /// * `additional_info`: Optional extra context shown by v3+ host UIs.
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

#[cfg(not(target_arch = "wasm32"))]
#[allow(
    unsafe_op_in_unsafe_fn,
    clippy::missing_safety_doc,
    clippy::too_many_arguments
)]
pub mod credman_v2 {
    use super::*;
    use crate::test_shim;

    #[allow(non_snake_case)]
    pub unsafe fn AddEntrySet(set_id: *const c_char, set_length: i32) {
        test_shim::record(test_shim::DisplayEvent::AddEntrySet {
            set_id: test_shim::c_str_to_string(set_id).unwrap_or_default(),
            set_length,
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddEntryToSet(
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
    ) {
        test_shim::record(test_shim::DisplayEvent::AddEntryToSet {
            cred_id: test_shim::c_str_to_string(cred_id).unwrap_or_default(),
            icon: test_shim::bytes_from_ptr(icon, icon_len),
            title: test_shim::c_str_to_string(title).unwrap_or_default(),
            subtitle: test_shim::c_str_to_string(subtitle),
            disclaimer: test_shim::c_str_to_string(disclaimer),
            warning: test_shim::c_str_to_string(warning),
            metadata: test_shim::c_str_to_string(metadata),
            set_id: test_shim::c_str_to_string(set_id).unwrap_or_default(),
            set_index,
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddFieldToEntrySet(
        cred_id: *const c_char,
        field_display_name: *const c_char,
        field_display_value: *const c_char,
        set_id: *const c_char,
        set_index: i32,
    ) {
        test_shim::record(test_shim::DisplayEvent::AddFieldToEntrySet {
            cred_id: test_shim::c_str_to_string(cred_id).unwrap_or_default(),
            field_display_name: test_shim::c_str_to_string(field_display_name).unwrap_or_default(),
            field_display_value: test_shim::c_str_to_string(field_display_value),
            set_id: test_shim::c_str_to_string(set_id).unwrap_or_default(),
            set_index,
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddPaymentEntryToSet(
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
    ) {
        test_shim::record(test_shim::DisplayEvent::AddPaymentEntryToSet {
            cred_id: test_shim::c_str_to_string(cred_id).unwrap_or_default(),
            merchant_name: test_shim::c_str_to_string(merchant_name).unwrap_or_default(),
            payment_method_name: test_shim::c_str_to_string(payment_method_name),
            payment_method_subtitle: test_shim::c_str_to_string(payment_method_subtitle),
            payment_method_icon: test_shim::bytes_from_ptr(
                payment_method_icon,
                payment_method_icon_len,
            ),
            transaction_amount: test_shim::c_str_to_string(transaction_amount).unwrap_or_default(),
            bank_icon: test_shim::bytes_from_ptr(bank_icon, bank_icon_len),
            payment_provider_icon: test_shim::bytes_from_ptr(
                payment_provider_icon,
                payment_provider_icon_len,
            ),
            metadata: test_shim::c_str_to_string(metadata),
            set_id: test_shim::c_str_to_string(set_id).unwrap_or_default(),
            set_index,
        });
    }

    #[allow(non_snake_case)]
    pub unsafe fn AddPaymentEntryToSetV2(
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
    ) {
        test_shim::record(test_shim::DisplayEvent::AddPaymentEntryToSetV2 {
            cred_id: test_shim::c_str_to_string(cred_id).unwrap_or_default(),
            merchant_name: test_shim::c_str_to_string(merchant_name).unwrap_or_default(),
            payment_method_name: test_shim::c_str_to_string(payment_method_name),
            payment_method_subtitle: test_shim::c_str_to_string(payment_method_subtitle),
            payment_method_icon: test_shim::bytes_from_ptr(
                payment_method_icon,
                payment_method_icon_len,
            ),
            transaction_amount: test_shim::c_str_to_string(transaction_amount).unwrap_or_default(),
            bank_icon: test_shim::bytes_from_ptr(bank_icon, bank_icon_len),
            payment_provider_icon: test_shim::bytes_from_ptr(
                payment_provider_icon,
                payment_provider_icon_len,
            ),
            additional_info: test_shim::c_str_to_string(additional_info),
            metadata: test_shim::c_str_to_string(metadata),
            set_id: test_shim::c_str_to_string(set_id).unwrap_or_default(),
            set_index,
        });
    }
}

// -------------------------------------------------------------------------
// Module: credman_v4
// System-only capabilities introduced in newer host versions.
// -------------------------------------------------------------------------
#[cfg(target_arch = "wasm32")]
pub mod credman_v4 {
    use super::*;

    #[link(wasm_import_module = "credman_v4")]
    unsafe extern "C" {
        /// Declares package identity metadata for system applications.
        ///
        /// # Parameters
        /// * `package_display_name`: Human-readable package/app name.
        /// * `package_icon`: Optional icon bytes pointer for package branding.
        /// * `package_icon_len`: Package icon byte length.
        ///
        /// # Notes
        /// Hosts generally restrict this to privileged/system contexts.
        pub fn SelfDeclarePackageInfo(
            package_display_name: *const c_char,
            package_icon: *const c_char,
            package_icon_len: usize,
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
pub mod credman_v4 {
    use super::*;
    use crate::test_shim;

    #[allow(non_snake_case)]
    pub unsafe fn SelfDeclarePackageInfo(
        package_display_name: *const c_char,
        package_icon: *const c_char,
        package_icon_len: usize,
    ) {
        test_shim::record(test_shim::DisplayEvent::SelfDeclarePackageInfo {
            package_display_name: test_shim::c_str_to_string(package_display_name)
                .unwrap_or_default(),
            package_icon: test_shim::bytes_from_ptr(package_icon, package_icon_len),
        });
    }
}
