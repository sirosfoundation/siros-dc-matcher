use android_credman_sys::CallingAppInfo;
use c8str::{C8Str, C8StrError, C8String};
use core::fmt;

/// The caller as the platform verified it. Trust it over any name or origin
/// inside the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingApp {
    package_name: C8String,
    origin: Option<C8String>,
}

impl CallingApp {
    /// Reads each field up to its first NUL inside the field. An empty
    /// origin is `None`.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) fn from_host(info: &CallingAppInfo) -> Result<Self, CallingAppError> {
        let package_name = C8Str::from_bytes_until_nul(&info.package_name)
            .map_err(CallingAppError::PackageName)?;
        let origin = C8Str::from_bytes_until_nul(&info.origin).map_err(CallingAppError::Origin)?;
        Ok(Self {
            package_name: package_name.into(),
            origin: (!origin.is_empty()).then(|| origin.into()),
        })
    }

    pub fn package_name(&self) -> &C8Str {
        &self.package_name
    }

    /// The page's origin when a browser calls; `None` for a native app.
    pub fn origin(&self) -> Option<&C8Str> {
        self.origin.as_deref()
    }
}

/// A `CallingAppInfo` field with no NUL inside it, or with bytes before the
/// NUL that are not UTF-8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingAppError {
    PackageName(C8StrError),
    Origin(C8StrError),
}

impl fmt::Display for CallingAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageName(cause) => write!(f, "calling app package name: {cause}"),
            Self::Origin(cause) => write!(f, "calling app origin: {cause}"),
        }
    }
}

impl std::error::Error for CallingAppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PackageName(cause) | Self::Origin(cause) => Some(cause),
        }
    }
}
