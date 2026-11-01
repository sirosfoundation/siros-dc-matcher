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
    /// Reads each field up to its first NUL, or to the end of a field the
    /// host filled to the brim. An empty origin is `None`.
    ///
    /// # Panics
    ///
    /// When a field's text is not UTF-8.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) fn from_host(info: &CallingAppInfo) -> Self {
        let origin = host_field(&info.origin, "origin");
        Self {
            package_name: host_field(&info.package_name, "package name"),
            origin: (!origin.is_empty()).then_some(origin),
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

/// One field of the host's report: its bytes up to the first NUL, or all of
/// them when the host filled the field to the brim.
///
/// # Panics
///
/// When those bytes are not UTF-8.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[expect(
    clippy::panic,
    reason = "GetCallingAppInfo fills each field with UTF-8 text; other bytes name no caller \
              the matcher can trust"
)]
fn host_field(field: &[u8], name: &str) -> C8String {
    let text = match field.iter().position(|&byte| byte == 0) {
        // `nul` is an index into `field`, so the split cannot panic.
        Some(nul) => field.split_at(nul).0,
        None => field,
    };
    match C8String::from_vec(text.to_vec()) {
        Ok(text) => text,
        // `text` holds no NUL, so the error is bytes that are not UTF-8:
        // the host broke the GetCallingAppInfo contract. The caller is the
        // one value every entry must carry verified, so the matcher has
        // nothing it may offer.
        Err(error) => panic!("calling app {name}: {error}"),
    }
}
