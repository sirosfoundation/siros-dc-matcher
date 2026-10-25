#![allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]

use std::ffi::{CStr, c_char, c_void};
use std::sync::{Mutex, MutexGuard};

#[derive(Debug, Clone)]
pub enum DisplayEvent {
    AddEntry {
        cred_id: i64,
        icon: Option<Vec<u8>>,
        title: Option<String>,
        subtitle: Option<String>,
        disclaimer: Option<String>,
        warning: Option<String>,
    },
    AddField {
        cred_id: i64,
        display_name: Option<String>,
        display_value: Option<String>,
    },
    AddStringIdEntry {
        cred_id: String,
        icon: Option<Vec<u8>>,
        title: String,
        subtitle: Option<String>,
        disclaimer: Option<String>,
        warning: Option<String>,
    },
    AddFieldForStringIdEntry {
        cred_id: String,
        display_name: String,
        display_value: Option<String>,
    },
    AddEntrySet {
        set_id: String,
        set_length: i32,
    },
    AddEntryToSet {
        cred_id: String,
        icon: Option<Vec<u8>>,
        title: String,
        subtitle: Option<String>,
        disclaimer: Option<String>,
        warning: Option<String>,
        metadata: Option<String>,
        set_id: String,
        set_index: i32,
    },
    AddFieldToEntrySet {
        cred_id: String,
        field_display_name: String,
        field_display_value: Option<String>,
        set_id: String,
        set_index: i32,
    },
    AddPaymentEntry {
        cred_id: String,
        merchant_name: String,
        payment_method_name: Option<String>,
        payment_method_subtitle: Option<String>,
        payment_method_icon: Option<Vec<u8>>,
        transaction_amount: String,
        bank_icon: Option<Vec<u8>>,
        payment_provider_icon: Option<Vec<u8>>,
    },
    AddPaymentEntryToSet {
        cred_id: String,
        merchant_name: String,
        payment_method_name: Option<String>,
        payment_method_subtitle: Option<String>,
        payment_method_icon: Option<Vec<u8>>,
        transaction_amount: String,
        bank_icon: Option<Vec<u8>>,
        payment_provider_icon: Option<Vec<u8>>,
        metadata: Option<String>,
        set_id: String,
        set_index: i32,
    },
    AddPaymentEntryToSetV2 {
        cred_id: String,
        merchant_name: String,
        payment_method_name: Option<String>,
        payment_method_subtitle: Option<String>,
        payment_method_icon: Option<Vec<u8>>,
        transaction_amount: String,
        bank_icon: Option<Vec<u8>>,
        payment_provider_icon: Option<Vec<u8>>,
        additional_info: Option<String>,
        metadata: Option<String>,
        set_id: String,
        set_index: i32,
    },
    AddInlineIssuanceEntry {
        cred_id: String,
        icon: Option<Vec<u8>>,
        title: String,
        subtitle: Option<String>,
    },
    SetAdditionalDisclaimerAndUrlForVerificationEntry {
        cred_id: String,
        secondary_disclaimer: Option<String>,
        url_display_text: Option<String>,
        url_value: Option<String>,
    },
    SelfDeclarePackageInfo {
        package_display_name: String,
        package_icon: Option<Vec<u8>>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct DisplaySnapshot {
    pub events: Vec<DisplayEvent>,
}

static DISPLAY: Mutex<DisplaySnapshot> = Mutex::new(DisplaySnapshot { events: Vec::new() });
static REQUEST: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static CREDENTIALS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub fn record(event: DisplayEvent) {
    lock(&DISPLAY).events.push(event);
}

pub fn snapshot_display() -> DisplaySnapshot {
    lock(&DISPLAY).clone()
}

pub fn take_display() -> DisplaySnapshot {
    std::mem::take(&mut *lock(&DISPLAY))
}

pub fn set_request(data: &[u8]) {
    *lock(&REQUEST) = data.to_vec();
}

pub fn set_credentials(data: &[u8]) {
    *lock(&CREDENTIALS) = data.to_vec();
}

pub fn request_len() -> u32 {
    lock(&REQUEST).len() as u32
}

pub fn credentials_len() -> u32 {
    lock(&CREDENTIALS).len() as u32
}

pub unsafe fn write_request(buffer: *mut c_void) {
    let data = lock(&REQUEST);
    if buffer.is_null() {
        return;
    }
    std::ptr::copy_nonoverlapping(data.as_ptr(), buffer as *mut u8, data.len());
}

pub unsafe fn read_credentials(buffer: *mut c_void, offset: usize, len: usize) -> usize {
    let data = lock(&CREDENTIALS);
    if buffer.is_null() || offset >= data.len() {
        return 0;
    }
    let available = data.len() - offset;
    let to_copy = available.min(len);
    std::ptr::copy_nonoverlapping(data.as_ptr().add(offset), buffer as *mut u8, to_copy);
    to_copy
}

pub unsafe fn c_str_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    Some(CStr::from_ptr(ptr).to_string_lossy().into_owned())
}

pub unsafe fn bytes_from_ptr(ptr: *const c_char, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr as *const u8, len).to_vec())
}
