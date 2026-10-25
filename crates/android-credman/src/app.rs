//! The calling app, as the platform verified it.

use android_credman_sys::CallingAppInfo;
use c8str::{C8Str, C8StrError};

/// The caller the host reported through `GetCallingAppInfo`.
///
/// This is the platform's statement of who is asking. A name or origin that
/// arrives inside the request is the request describing itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallingApp {
    raw: CallingAppInfo,
}

impl CallingApp {
    /// Wraps the fixed-size struct the host filled.
    pub const fn from_raw(raw: CallingAppInfo) -> Self {
        Self { raw }
    }

    /// The fixed-size struct as the host filled it.
    pub const fn raw(&self) -> &CallingAppInfo {
        &self.raw
    }

    /// The Android package name of the caller.
    ///
    /// # Errors
    ///
    /// [`C8StrError`] when the field holds no NUL or is not UTF-8 before it.
    pub const fn package_name(&self) -> Result<&C8Str, C8StrError> {
        C8Str::from_bytes_until_nul(&self.raw.package_name)
    }

    /// The web origin when a browser calls for a page; empty for a native
    /// app.
    ///
    /// # Errors
    ///
    /// [`C8StrError`] when the field holds no NUL or is not UTF-8 before it.
    pub const fn origin(&self) -> Result<&C8Str, C8StrError> {
        C8Str::from_bytes_until_nul(&self.raw.origin)
    }
}
