use android_credman_sys::CallingAppInfo;
use c8str::{C8Str, C8StrError};

/// The caller as the platform verified it. Trust it over any name or origin
/// inside the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallingApp {
    raw: CallingAppInfo,
}

impl CallingApp {
    pub const fn from_raw(raw: CallingAppInfo) -> Self {
        Self { raw }
    }

    pub const fn raw(&self) -> &CallingAppInfo {
        &self.raw
    }

    /// # Errors
    ///
    /// [`C8StrError`] when the field holds no NUL or is not UTF-8 before it.
    pub const fn package_name(&self) -> Result<&C8Str, C8StrError> {
        C8Str::from_bytes_until_nul(&self.raw.package_name)
    }

    /// Empty for a native app.
    ///
    /// # Errors
    ///
    /// [`C8StrError`] when the field holds no NUL or is not UTF-8 before it.
    pub const fn origin(&self) -> Result<&C8Str, C8StrError> {
        C8Str::from_bytes_until_nul(&self.raw.origin)
    }
}
