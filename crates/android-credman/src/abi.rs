use crate::{
    CredentialSet, Field, InlineIssuanceEntry, PackageInfo, PaymentEntry, StringIdEntry,
    VerificationEntryUpdate,
};
use android_credman_sys::{credman, credman_v2, credman_v4};
use std::ffi::{CStr, c_char};
use std::ptr;

fn opt_cstr_ptr(value: Option<&CStr>) -> *const c_char {
    value.map_or(ptr::null(), |value| value.as_ptr())
}

fn to_bytes_ptr_len(b: Option<&[u8]>) -> (*const c_char, usize) {
    match b {
        Some(bytes) => (bytes.as_ptr() as *const c_char, bytes.len()),
        None => (ptr::null(), 0),
    }
}

pub fn add_string_id_entry(entry: &StringIdEntry<'_>) {
    let p_cred_id = entry.cred_id.as_ptr();
    let (p_icon, len_icon) = to_bytes_ptr_len(entry.icon.as_deref());
    let p_title = entry.title.as_ptr();
    let p_subtitle = opt_cstr_ptr(entry.subtitle.as_deref());
    let p_disclaimer = opt_cstr_ptr(entry.disclaimer.as_deref());
    let p_warning = opt_cstr_ptr(entry.warning.as_deref());

    unsafe {
        credman::AddStringIdEntry(
            p_cred_id,
            p_icon,
            len_icon,
            p_title,
            p_subtitle,
            p_disclaimer,
            p_warning,
        );
    }
}

pub fn add_field_for_string_id_entry(cred_id: &CStr, field: &Field) {
    let p_cred_id = cred_id.as_ptr();
    let p_name = field.display_name.as_ptr();
    let p_val = opt_cstr_ptr(field.display_value.as_deref());

    unsafe {
        credman::AddFieldForStringIdEntry(p_cred_id, p_name, p_val);
    }
}

pub fn add_payment_entry(entry: &PaymentEntry<'_>) {
    let p_cred_id = entry.cred_id.as_ptr();
    let p_merchant = entry.merchant_name.as_ptr();
    let p_pm_name = opt_cstr_ptr(entry.payment_method_name.as_deref());
    let p_pm_sub = opt_cstr_ptr(entry.payment_method_subtitle.as_deref());
    let (p_pm_icon, len_pm_icon) = to_bytes_ptr_len(entry.payment_method_icon.as_deref());
    let p_amount = entry.transaction_amount.as_ptr();
    let (p_bank_icon, len_bank_icon) = to_bytes_ptr_len(entry.bank_icon.as_deref());
    let (p_pp_icon, len_pp_icon) = to_bytes_ptr_len(entry.payment_provider_icon.as_deref());

    unsafe {
        credman::AddPaymentEntry(
            p_cred_id,
            p_merchant,
            p_pm_name,
            p_pm_sub,
            p_pm_icon,
            len_pm_icon,
            p_amount,
            p_bank_icon,
            len_bank_icon,
            p_pp_icon,
            len_pp_icon,
        );
    }
}

pub fn add_inline_issuance_entry(entry: &InlineIssuanceEntry<'_>) {
    let p_cred_id = entry.cred_id.as_ptr();
    let (p_icon, len_icon) = to_bytes_ptr_len(entry.icon.as_deref());
    let p_title = entry.title.as_ptr();
    let p_subtitle = opt_cstr_ptr(entry.subtitle.as_deref());

    unsafe {
        credman::AddInlineIssuanceEntry(p_cred_id, p_icon, len_icon, p_title, p_subtitle);
    }
}

pub fn set_additional_disclaimer_and_url(update: &VerificationEntryUpdate<'_>) {
    let p_cred_id = update.cred_id.as_ptr();
    let p_disc = opt_cstr_ptr(update.secondary_disclaimer.as_deref());
    let p_url_txt = opt_cstr_ptr(update.url_display_text.as_deref());
    let p_url_val = opt_cstr_ptr(update.url_value.as_deref());

    unsafe {
        credman::SetAdditionalDisclaimerAndUrlForVerificationEntry(
            p_cred_id, p_disc, p_url_txt, p_url_val,
        );
    }
}

// --- V2 ---

pub fn add_entry_set(set: &CredentialSet<'_>) {
    let p_set_id = set.set_id.as_ptr();
    unsafe {
        credman_v2::AddEntrySet(p_set_id, set.slots.len() as i32);
    }
}

pub fn add_entry_to_set(entry: &StringIdEntry<'_>, set_id: &CStr, set_index: i32) {
    let p_cred_id = entry.cred_id.as_ptr();
    let (p_icon, len_icon) = to_bytes_ptr_len(entry.icon.as_deref());
    let p_title = entry.title.as_ptr();
    let p_subtitle = opt_cstr_ptr(entry.subtitle.as_deref());
    let p_disclaimer = opt_cstr_ptr(entry.disclaimer.as_deref());
    let p_warning = opt_cstr_ptr(entry.warning.as_deref());
    let p_metadata = opt_cstr_ptr(entry.metadata.as_deref());
    let p_set_id = set_id.as_ptr();

    unsafe {
        credman_v2::AddEntryToSet(
            p_cred_id,
            p_icon,
            len_icon,
            p_title,
            p_subtitle,
            p_disclaimer,
            p_warning,
            p_metadata,
            p_set_id,
            set_index,
        );
    }
}

pub fn add_field_to_entry_set(field: &Field, cred_id: &CStr, set_id: &CStr, set_index: i32) {
    let p_cred_id = cred_id.as_ptr();
    let p_name = field.display_name.as_ptr();
    let p_val = opt_cstr_ptr(field.display_value.as_deref());
    let p_set_id = set_id.as_ptr();

    unsafe {
        credman_v2::AddFieldToEntrySet(p_cred_id, p_name, p_val, p_set_id, set_index);
    }
}

pub fn add_payment_entry_to_set(entry: &PaymentEntry<'_>, set_id: &CStr, set_index: i32) {
    let p_cred_id = entry.cred_id.as_ptr();
    let p_merchant = entry.merchant_name.as_ptr();
    let p_pm_name = opt_cstr_ptr(entry.payment_method_name.as_deref());
    let p_pm_sub = opt_cstr_ptr(entry.payment_method_subtitle.as_deref());
    let (p_pm_icon, len_pm_icon) = to_bytes_ptr_len(entry.payment_method_icon.as_deref());
    let p_amount = entry.transaction_amount.as_ptr();
    let (p_bank_icon, len_bank_icon) = to_bytes_ptr_len(entry.bank_icon.as_deref());
    let (p_pp_icon, len_pp_icon) = to_bytes_ptr_len(entry.payment_provider_icon.as_deref());
    let p_metadata = opt_cstr_ptr(entry.metadata.as_deref());
    let p_set_id = set_id.as_ptr();

    unsafe {
        credman_v2::AddPaymentEntryToSet(
            p_cred_id,
            p_merchant,
            p_pm_name,
            p_pm_sub,
            p_pm_icon,
            len_pm_icon,
            p_amount,
            p_bank_icon,
            len_bank_icon,
            p_pp_icon,
            len_pp_icon,
            p_metadata,
            p_set_id,
            set_index,
        );
    }
}

pub fn add_payment_entry_to_set_v2(entry: &PaymentEntry<'_>, set_id: &CStr, set_index: i32) {
    let p_cred_id = entry.cred_id.as_ptr();
    let p_merchant = entry.merchant_name.as_ptr();
    let p_pm_name = opt_cstr_ptr(entry.payment_method_name.as_deref());
    let p_pm_sub = opt_cstr_ptr(entry.payment_method_subtitle.as_deref());
    let (p_pm_icon, len_pm_icon) = to_bytes_ptr_len(entry.payment_method_icon.as_deref());
    let p_amount = entry.transaction_amount.as_ptr();
    let (p_bank_icon, len_bank_icon) = to_bytes_ptr_len(entry.bank_icon.as_deref());
    let (p_pp_icon, len_pp_icon) = to_bytes_ptr_len(entry.payment_provider_icon.as_deref());
    let p_additional_info = opt_cstr_ptr(entry.additional_info.as_deref());
    let p_metadata = opt_cstr_ptr(entry.metadata.as_deref());
    let p_set_id = set_id.as_ptr();

    unsafe {
        credman_v2::AddPaymentEntryToSetV2(
            p_cred_id,
            p_merchant,
            p_pm_name,
            p_pm_sub,
            p_pm_icon,
            len_pm_icon,
            p_amount,
            p_bank_icon,
            len_bank_icon,
            p_pp_icon,
            len_pp_icon,
            p_additional_info,
            p_metadata,
            p_set_id,
            set_index,
        );
    }
}

pub fn self_declare_package_info(info: &PackageInfo<'_>) {
    let p_name = info.package_display_name.as_ptr();
    let (p_icon, len_icon) = to_bytes_ptr_len(info.package_icon.as_deref());
    unsafe {
        credman_v4::SelfDeclarePackageInfo(p_name, p_icon, len_icon);
    }
}

pub fn get_request_size() -> u32 {
    let mut size: u32 = 0;
    unsafe {
        credman::GetRequestSize(&mut size);
    }
    size
}

pub fn get_request_buffer(buffer: &mut [u8]) {
    unsafe {
        credman::GetRequestBuffer(buffer.as_mut_ptr() as *mut _);
    }
}

pub fn get_credentials_size() -> u32 {
    let mut size: u32 = 0;
    unsafe {
        credman::GetCredentialsSize(&mut size);
    }
    size
}

pub fn read_credentials_buffer(buffer: &mut [u8], offset: usize) -> usize {
    unsafe { credman::ReadCredentialsBuffer(buffer.as_mut_ptr() as *mut _, offset, buffer.len()) }
}

pub fn get_wasm_version() -> u32 {
    let mut version: u32 = 0;
    unsafe {
        credman::GetWasmVersion(&mut version);
    }
    version
}

pub fn get_calling_app_info() -> android_credman_sys::CallingAppInfo {
    let mut info = android_credman_sys::CallingAppInfo {
        package_name: [0; 256],
        origin: [0; 512],
    };
    unsafe {
        credman::GetCallingAppInfo(&mut info);
    }
    info
}
