//! Every pointer passed here comes from a borrowed `&C8Str`, `&[u8]` or an
//! `Option` of one (NULL for `None`), so each call meets the rules of
//! `ABI.md`.

use crate::app::{CallingApp, CallingAppError};
use crate::entry::{InlineIssuanceEntry, LegacyEntry, PaymentEntry, StringIdEntry};
use crate::version::{WasmVersion, V4};
use android_credman_sys::{credman, v4, CallingAppInfo};
use c8str::C8Str;
use core::ffi::c_void;
use core::{fmt, ptr};
use std::collections::TryReserveError;

/// The host of one matcher invocation: the verifier's request, the wallet's
/// credentials, the calling app, and the standalone entries. Entry sets go
/// through the [`V2`](crate::V2) token from [`Host::version`].
#[derive(Debug, Clone, Copy)]
pub struct Host {
    version: WasmVersion,
}

impl Host {
    /// Reads the host level with [`GetWasmVersion`](credman::GetWasmVersion).
    /// A matcher connects first, here or with [`Host::connect_with`].
    pub fn connect() -> Self {
        let mut level = 0u32;
        // SAFETY: `level` is a live u32 the host writes once.
        unsafe { credman::GetWasmVersion(&mut level) };
        Self {
            version: WasmVersion::reported(level),
        }
    }

    /// The reported level, which hands out the token of each level the host
    /// reaches.
    pub fn version(&self) -> WasmVersion {
        self.version
    }

    /// The verifier's request: the Digital Credentials API request as JSON,
    /// read with [`GetRequestSize`](credman::GetRequestSize) and
    /// [`GetRequestBuffer`](credman::GetRequestBuffer). A matcher reads it
    /// once.
    ///
    /// # Errors
    ///
    /// [`TryReserveError`] when the reported length cannot be allocated.
    pub fn request(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut size = 0u32;
        // SAFETY: `size` is a live u32 the host writes once.
        unsafe { credman::GetRequestSize(&mut size) };
        let mut request = zeroed(size as usize)?;
        // SAFETY: the buffer holds the `size` bytes the host writes.
        unsafe { credman::GetRequestBuffer(request.as_mut_ptr().cast::<c_void>()) };
        Ok(request)
    }

    /// The length in bytes of the credential blob the wallet registered, from
    /// [`GetCredentialsSize`](credman::GetCredentialsSize).
    pub fn credentials_size(&self) -> usize {
        let mut size = 0u32;
        // SAFETY: `size` is a live u32 the host writes once.
        unsafe { credman::GetCredentialsSize(&mut size) };
        size as usize
    }

    /// Copies the blob's bytes from `offset` into `buffer` with
    /// [`ReadCredentialsBuffer`](credman::ReadCredentialsBuffer). Returns the
    /// count the host copied, which may be lower than `buffer.len()` and is 0
    /// past the end.
    ///
    /// # Errors
    ///
    /// [`CredentialsError::Overrun`] when the host reports more bytes than
    /// `buffer` holds.
    pub fn read_credentials_at(
        &self,
        buffer: &mut [u8],
        offset: usize,
    ) -> Result<usize, CredentialsError> {
        let asked = buffer.len();
        // SAFETY: the buffer is valid for `asked` bytes, the most the host
        // writes.
        let copied = unsafe {
            credman::ReadCredentialsBuffer(buffer.as_mut_ptr().cast::<c_void>(), offset, asked)
        };
        if copied > asked {
            return Err(CredentialsError::Overrun { asked, copied });
        }
        Ok(copied)
    }

    /// The credential blob the wallet registered, read in as many calls as
    /// the host needs. A matcher reads it once.
    ///
    /// # Errors
    ///
    /// [`CredentialsError`] when the reported length cannot be allocated,
    /// the host copies nothing before that length, or it reports more bytes
    /// than it was asked for.
    pub fn credentials(&self) -> Result<Vec<u8>, CredentialsError> {
        let size = self.credentials_size();
        let mut blob = zeroed(size).map_err(CredentialsError::TooLarge)?;
        let mut delivered = 0;
        while let Some(rest) = blob.get_mut(delivered..).filter(|rest| !rest.is_empty()) {
            let copied = self.read_credentials_at(rest, delivered)?;
            if copied == 0 {
                return Err(CredentialsError::Incomplete { delivered, size });
            }
            // At most `rest.len()`, so `delivered` stays within `size`.
            delivered += copied;
        }
        Ok(blob)
    }

    /// The app that called the Digital Credentials API, read with
    /// [`GetCallingAppInfo`](credman::GetCallingAppInfo) and converted once.
    ///
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

    /// Adds a standalone verification entry, then its fields, then its link,
    /// with [`AddStringIdEntry`](credman::AddStringIdEntry),
    /// [`AddFieldForStringIdEntry`](credman::AddFieldForStringIdEntry) and
    /// [`SetAdditionalDisclaimerAndUrlForVerificationEntry`](credman::SetAdditionalDisclaimerAndUrlForVerificationEntry).
    /// For a host below level 2, which has no sets.
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

    /// Adds a standalone entry named by a number, then its fields, with
    /// [`AddEntry`](credman::AddEntry) and [`AddField`](credman::AddField).
    /// Google's header deprecates them for [`Host::add_string_id_entry`].
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

    /// Adds a standalone payment entry with
    /// [`AddPaymentEntry`](credman::AddPaymentEntry). For a host below level
    /// 2, which has no sets.
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

    /// Adds an entry that offers to issue a credential the wallet lacks, with
    /// [`AddInlineIssuanceEntry`](credman::AddInlineIssuanceEntry).
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

/// `size` zero bytes, or the reason they cannot be allocated.
fn zeroed(size: usize) -> Result<Vec<u8>, TryReserveError> {
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(size)?;
    buffer.resize(size, 0);
    Ok(buffer)
}

/// Why the credential blob could not be read. Every variant but `TooLarge`
/// is the host breaking the
/// [`ReadCredentialsBuffer`](credman::ReadCredentialsBuffer) contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialsError {
    /// The blob's reported length cannot be allocated.
    TooLarge(TryReserveError),
    /// The host reported copying `copied` bytes into a buffer of `asked`.
    Overrun { asked: usize, copied: usize },
    /// The host copied nothing at byte `delivered` of the `size` bytes it
    /// reported.
    Incomplete { delivered: usize, size: usize },
    /// The host reported copying `copied` bytes from `offset`, past the
    /// `size` bytes it reported.
    PastEnd {
        offset: usize,
        copied: usize,
        size: usize,
    },
}

impl fmt::Display for CredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(cause) => write!(f, "credential blob too large: {cause}"),
            Self::Overrun { asked, copied } => {
                write!(
                    f,
                    "host reported {copied} credential bytes for a {asked}-byte buffer"
                )
            }
            Self::Incomplete { delivered, size } => {
                write!(f, "host stopped at credential byte {delivered} of {size}")
            }
            Self::PastEnd {
                offset,
                copied,
                size,
            } => write!(
                f,
                "host reported {copied} credential bytes from {offset}, past its size {size}"
            ),
        }
    }
}

impl std::error::Error for CredentialsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TooLarge(cause) => Some(cause),
            Self::Overrun { .. } | Self::Incomplete { .. } | Self::PastEnd { .. } => None,
        }
    }
}

/// What [`Host::connect_with`] declares to the host after reading its level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostOptions<'a> {
    /// Declared once with [`SelfDeclarePackageInfo`](v4::SelfDeclarePackageInfo)
    /// when the host reaches level 4, and skipped below it. Google's header
    /// says the call works for system apps only; what the picker does with
    /// the values is unconfirmed.
    pub package_info: Option<PackageInfo<'a>>,
}

/// The wallet app's display name and icon, for
/// [`HostOptions::package_info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageInfo<'a> {
    pub display_name: &'a C8Str,
    /// At least one byte (conservative).
    pub icon: &'a [u8],
}

impl Host {
    /// Reads the host level as [`Host::connect`] does, then makes the
    /// declarations `options` holds that the level allows.
    pub fn connect_with(options: HostOptions<'_>) -> Self {
        let host = Self::connect();
        if let (Some(info), Some(level)) = (options.package_info, host.version.v4()) {
            level.declare_package_info(&info);
        }
        host
    }
}

impl V4 {
    fn declare_package_info(self, info: &PackageInfo<'_>) {
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
