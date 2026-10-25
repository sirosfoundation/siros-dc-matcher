//! Every pointer passed here comes from a borrowed `&C8Str`, `&[u8]` or an
//! `Option` of one (NULL for `None`), so each call meets the rules of
//! `ABI.md`.

use crate::app::CallingApp;
use crate::entry::{
    Field, InlineIssuanceEntry, LegacyEntry, PaymentDisplay, PaymentEntry, StringIdEntry,
    VerificationDisplay,
};
use crate::version::WasmVersion;
use alloc::vec;
use alloc::vec::Vec;
use android_credman_sys::{c_char, credman, CallingAppInfo};
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

    pub fn calling_app(&self) -> CallingApp {
        let mut info = CallingAppInfo::ZEROED;
        // SAFETY: `info` is a whole CallingAppInfo the host fills.
        unsafe { credman::GetCallingAppInfo(&mut info) };
        CallingApp::from_raw(info)
    }

    pub fn add_string_id_entry(&self, entry: &StringIdEntry<'_>) {
        let id = entry.cred_id.as_ptr();
        let d = VerificationParts::of(&entry.display);
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddStringIdEntry(
                id,
                d.icon.0,
                d.icon.1,
                d.title,
                d.subtitle,
                d.disclaimer,
                d.warning,
            );
        }
        entry
            .fields
            .iter()
            .for_each(|field| standalone_field(id, field));
        if let Some(link) = entry.link {
            // SAFETY: see the module documentation.
            unsafe {
                credman::SetAdditionalDisclaimerAndUrlForVerificationEntry(
                    id,
                    link.secondary_disclaimer.as_ptr(),
                    link.url_display_text.as_ptr(),
                    link.url_value.as_ptr(),
                );
            }
        }
    }

    pub fn add_legacy_entry(&self, entry: &LegacyEntry<'_>) {
        let (icon, icon_len) = icon_parts(entry.icon);
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddEntry(
                entry.cred_id,
                icon,
                icon_len,
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
        let p = PaymentParts::of(&entry.display);
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddPaymentEntry(
                entry.cred_id.as_ptr(),
                p.merchant,
                p.method,
                p.method_subtitle,
                p.method_icon.0,
                p.method_icon.1,
                p.amount,
                p.bank_icon.0,
                p.bank_icon.1,
                p.provider_icon.0,
                p.provider_icon.1,
            );
        }
    }

    pub fn add_inline_issuance_entry(&self, entry: &InlineIssuanceEntry<'_>) {
        let (icon, icon_len) = optional_icon_parts(entry.icon);
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddInlineIssuanceEntry(
                entry.cred_id.as_ptr(),
                icon,
                icon_len,
                optional(entry.title),
                optional(entry.subtitle),
            );
        }
    }
}

fn standalone_field(id: *const c_char, field: &Field<'_>) {
    // SAFETY: see the module documentation.
    unsafe { credman::AddFieldForStringIdEntry(id, field.name.as_ptr(), optional(field.value)) };
}

pub(crate) fn optional(text: Option<&C8Str>) -> *const c_char {
    text.map_or(ptr::null(), C8Str::as_ptr)
}

pub(crate) fn icon_parts(icon: &[u8]) -> (*const c_char, usize) {
    (icon.as_ptr().cast::<c_char>(), icon.len())
}

pub(crate) fn optional_icon_parts(icon: Option<&[u8]>) -> (*const c_char, usize) {
    icon.map_or((ptr::null(), 0), icon_parts)
}

pub(crate) struct PaymentParts {
    pub(crate) merchant: *const c_char,
    pub(crate) method: *const c_char,
    pub(crate) method_subtitle: *const c_char,
    pub(crate) method_icon: (*const c_char, usize),
    pub(crate) amount: *const c_char,
    pub(crate) bank_icon: (*const c_char, usize),
    pub(crate) provider_icon: (*const c_char, usize),
}

impl PaymentParts {
    pub(crate) fn of(display: &PaymentDisplay<'_>) -> Self {
        Self {
            merchant: display.merchant_name.as_ptr(),
            method: display.payment_method_name.as_ptr(),
            method_subtitle: optional(display.payment_method_subtitle),
            method_icon: icon_parts(display.payment_method_icon),
            amount: display.transaction_amount.as_ptr(),
            bank_icon: optional_icon_parts(display.bank_icon),
            provider_icon: optional_icon_parts(display.payment_provider_icon),
        }
    }
}

pub(crate) struct VerificationParts {
    pub(crate) icon: (*const c_char, usize),
    pub(crate) title: *const c_char,
    pub(crate) subtitle: *const c_char,
    pub(crate) disclaimer: *const c_char,
    pub(crate) warning: *const c_char,
}

impl VerificationParts {
    pub(crate) fn of(display: &VerificationDisplay<'_>) -> Self {
        Self {
            icon: icon_parts(display.icon),
            title: display.title.as_ptr(),
            subtitle: optional(display.subtitle),
            disclaimer: optional(display.disclaimer),
            warning: optional(display.warning),
        }
    }
}

#[cfg(feature = "v4")]
impl crate::version::V4 {
    pub fn self_declare_package_info(&self, info: &crate::entry::PackageInfo<'_>) {
        let (icon, icon_len) = icon_parts(info.icon);
        // SAFETY: see the module documentation.
        unsafe {
            android_credman_sys::credman_v4::SelfDeclarePackageInfo(
                info.display_name.as_ptr(),
                icon,
                icon_len,
            );
        }
    }
}
