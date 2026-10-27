use android_credman_sys::CallingAppInfo;
use c8str::{C8Str, C8String};

/// The app that called the Digital Credentials API, as the platform verified
/// it: its package name and, for a browser, the page's origin. Trust it over
/// any name or origin inside the request. [`Host::calling_app`] reads it
/// with [`GetCallingAppInfo`].
///
/// [`Host::calling_app`]: crate::Host::calling_app
/// [`GetCallingAppInfo`]: android_credman_sys::credman::GetCallingAppInfo
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingApp {
    package_name: C8String,
    origin: Option<C8String>,
}

impl CallingApp {
    /// Reads each field up to its first NUL inside the field. An empty
    /// origin is `None`.
    ///
    /// # Panics
    ///
    /// When a field holds no NUL, or bytes before it that are not UTF-8.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) fn from_host(info: &CallingAppInfo) -> Self {
        let package_name = host_field(&info.package_name, "package name");
        let origin = host_field(&info.origin, "origin");
        Self {
            package_name: package_name.into(),
            origin: (!origin.is_empty()).then(|| origin.into()),
        }
    }

    /// The Android package name of the calling app, such as a browser's.
    pub fn package_name(&self) -> &C8Str {
        &self.package_name
    }

    /// The page's origin when a browser calls; `None` for a native app.
    pub fn origin(&self) -> Option<&C8Str> {
        self.origin.as_deref()
    }
}

/// One field of the host's report, up to its NUL.
///
/// # Panics
///
/// When `field` holds no NUL, or bytes before it that are not UTF-8.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[expect(
    clippy::panic,
    reason = "GetCallingAppInfo fills each fixed-size field with NUL-terminated text; \
              a field without it names no caller the matcher can trust"
)]
fn host_field<'a>(field: &'a [u8], name: &str) -> &'a C8Str {
    match C8Str::from_bytes_until_nul(field) {
        Ok(text) => text,
        // The host broke the GetCallingAppInfo contract. The caller is
        // the one value every entry must carry verified, so the matcher
        // has nothing it may offer.
        Err(error) => panic!("calling app {name}: {error}"),
    }
}
