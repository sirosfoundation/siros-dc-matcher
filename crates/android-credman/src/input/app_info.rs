use crate::abi;
use c8str::C8Str;
use core::ffi::c_char;

/// Information about the application requesting the credential.
#[derive(Debug, Clone, Copy)]
pub struct CallingAppInfo(android_credman_sys::CallingAppInfo);

impl CallingAppInfo {
    /// Android package name of the caller.
    ///
    /// # Safety
    /// The ABI guarantees this is a valid UTF-8, NUL-terminated C string.
    pub fn package_name(&self) -> &C8Str {
        c8_from_abi(&self.0.package_name)
    }

    /// Web origin of the caller.
    ///
    /// # Safety
    /// The ABI guarantees this is a valid UTF-8, NUL-terminated C string.
    pub fn origin(&self) -> &C8Str {
        c8_from_abi(&self.0.origin)
    }
}

/// Gets information about the application requesting the credential as a wrapper.
pub fn get_calling_app_info() -> CallingAppInfo {
    CallingAppInfo(abi::get_calling_app_info())
}

fn c8_from_abi(bytes: &[u8]) -> &C8Str {
    unsafe {
        // Safety: ABI guarantees valid UTF-8 with a trailing NUL.
        C8Str::from_ptr_unchecked(bytes.as_ptr() as *const c_char)
    }
}
