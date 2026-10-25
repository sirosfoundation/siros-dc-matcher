//! Every pointer passed here comes from a borrowed `&C8Str`, `&[u8]` or an
//! `Option` of one (NULL for `None`), so each call meets the rules of
//! `ABI.md`.

use crate::app::{CallingApp, CallingAppError};
use crate::entry::{InlineIssuanceEntry, LegacyEntry, PackageInfo, PaymentEntry, StringIdEntry};
use crate::version::{WasmVersion, V4};
use android_credman_sys::{credman, v4, CallingAppInfo};
use c8str::C8Str;
use core::ffi::c_void;
use core::ptr;

#[derive(Debug, Clone, Copy)]
pub struct Host {
    version: WasmVersion,
}

impl Host {
    /// Reads `GetWasmVersion`.
    pub fn connect() -> Self {
        let mut level = 0u32;
        // SAFETY: `level` is a live u32 the host writes once.
        unsafe { credman::GetWasmVersion(&mut level) };
        Self {
            version: WasmVersion::reported(level),
        }
    }

    /// Hands out the capability tokens.
    pub fn version(&self) -> WasmVersion {
        self.version
    }

    pub fn request(&self) -> Vec<u8> {
        let mut size = 0u32;
        // SAFETY: `size` is a live u32 the host writes once.
        unsafe { credman::GetRequestSize(&mut size) };
        let mut request = vec![0u8; size as usize];
        // SAFETY: the buffer holds the `size` bytes the host writes.
        unsafe { credman::GetRequestBuffer(request.as_mut_ptr().cast::<c_void>()) };
        request
    }

    pub fn credentials_size(&self) -> usize {
        let mut size = 0u32;
        // SAFETY: `size` is a live u32 the host writes once.
        unsafe { credman::GetCredentialsSize(&mut size) };
        size as usize
    }

    /// Returns the count the host copied, which may be lower than
    /// `buffer.len()`.
    pub fn read_credentials_at(&self, buffer: &mut [u8], offset: usize) -> usize {
        // SAFETY: the buffer is valid for `buffer.len()` bytes, the most the
        // host writes.
        unsafe {
            credman::ReadCredentialsBuffer(
                buffer.as_mut_ptr().cast::<c_void>(),
                offset,
                buffer.len(),
            )
        }
    }

    /// Reads until the reported size or until a read returns nothing, and
    /// returns the bytes delivered.
    pub fn credentials(&self) -> Vec<u8> {
        let size = self.credentials_size();
        let mut blob = vec![0u8; size];
        let mut offset = 0;
        while offset < size {
            let copied = self.read_credentials_at(blob.split_at_mut(offset).1, offset);
            if copied == 0 {
                break;
            }
            // Any value at or past `size` ends the loop, so saturating keeps
            // the arithmetic defined without changing the outcome.
            offset = offset.saturating_add(copied);
        }
        blob.truncate(offset);
        blob
    }

    /// # Errors
    ///
    /// [`CallingAppError`] when a field holds no NUL or is not UTF-8 before
    /// it.
    pub fn calling_app(&self) -> Result<CallingApp, CallingAppError> {
        let mut info = CallingAppInfo::ZEROED;
        // SAFETY: `info` is a whole CallingAppInfo the host fills.
        unsafe { credman::GetCallingAppInfo(&mut info) };
        CallingApp::from_host(&info)
    }

    pub fn add_string_id_entry(&self, entry: &StringIdEntry<'_>) {
        let display = &entry.display;
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddStringIdEntry(
                entry.cred_id.as_ptr(),
                display.icon.as_ptr().cast(),
                display.icon.len(),
                display.title.as_ptr(),
                display.subtitle.map_or(ptr::null(), C8Str::as_ptr),
                display.disclaimer.map_or(ptr::null(), C8Str::as_ptr),
                display.warning.map_or(ptr::null(), C8Str::as_ptr),
            );
        }
        for field in entry.fields {
            // SAFETY: see the module documentation.
            unsafe {
                credman::AddFieldForStringIdEntry(
                    entry.cred_id.as_ptr(),
                    field.name.as_ptr(),
                    field.value.map_or(ptr::null(), C8Str::as_ptr),
                );
            }
        }
        if let Some(link) = entry.link {
            // SAFETY: see the module documentation.
            unsafe {
                credman::SetAdditionalDisclaimerAndUrlForVerificationEntry(
                    entry.cred_id.as_ptr(),
                    link.secondary_disclaimer.as_ptr(),
                    link.url_display_text.as_ptr(),
                    link.url_value.as_ptr(),
                );
            }
        }
    }

    pub fn add_legacy_entry(&self, entry: &LegacyEntry<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddEntry(
                entry.cred_id,
                entry.icon.as_ptr().cast(),
                entry.icon.len(),
                entry.title.as_ptr(),
                entry.subtitle.as_ptr(),
                entry.disclaimer.as_ptr(),
                entry.warning.as_ptr(),
            );
        }
        for field in entry.fields {
            // SAFETY: see the module documentation.
            unsafe { credman::AddField(entry.cred_id, field.name.as_ptr(), field.value.as_ptr()) };
        }
    }

    pub fn add_payment_entry(&self, entry: &PaymentEntry<'_>) {
        let display = &entry.display;
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddPaymentEntry(
                entry.cred_id.as_ptr(),
                display.merchant_name.as_ptr(),
                display.payment_method_name.as_ptr(),
                display
                    .payment_method_subtitle
                    .map_or(ptr::null(), C8Str::as_ptr),
                display.payment_method_icon.as_ptr().cast(),
                display.payment_method_icon.len(),
                display.transaction_amount.as_ptr(),
                display.bank_icon.map_or(ptr::null(), <[u8]>::as_ptr).cast(),
                display.bank_icon.map_or(0, <[u8]>::len),
                display
                    .payment_provider_icon
                    .map_or(ptr::null(), <[u8]>::as_ptr)
                    .cast(),
                display.payment_provider_icon.map_or(0, <[u8]>::len),
            );
        }
    }

    pub fn add_inline_issuance_entry(&self, entry: &InlineIssuanceEntry<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddInlineIssuanceEntry(
                entry.cred_id.as_ptr(),
                entry.icon.map_or(ptr::null(), <[u8]>::as_ptr).cast(),
                entry.icon.map_or(0, <[u8]>::len),
                entry.title.map_or(ptr::null(), C8Str::as_ptr),
                entry.subtitle.map_or(ptr::null(), C8Str::as_ptr),
            );
        }
    }
}

impl V4 {
    pub fn self_declare_package_info(&self, info: &PackageInfo<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            v4::SelfDeclarePackageInfo(
                info.display_name.as_ptr(),
                info.icon.as_ptr().cast(),
                info.icon.len(),
            );
        }
    }
}
