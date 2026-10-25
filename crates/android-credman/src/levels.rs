//! The host's functions as safe calls, one trait per host level. Each level
//! implies the one below. [`Host::credman`](crate::Host::credman) hands out
//! the base, [`Credman`]; [`Credman::version`] grants the singleton of a
//! higher level when the level `GetWasmVersion` reported reaches it. Every
//! call is static, so a binary imports only the functions it calls.
//!
//! Every pointer passed here comes from a borrowed `&C8Str`, `&[u8]` or an
//! `Option` of one (NULL for `None`), so each call meets the rules of
//! `ABI.md`.

use crate::entry::{
    DelegationType, Field, InlineIssuanceEntry, LegacyDisplay, LegacyField, PackageInfo,
    PaymentDisplay, VerificationDisplay, VerificationLink,
};
use android_credman_sys::{credman, v2, v3, v4, v5, v6, v7, CallingAppInfo};
use c8str::C8Str;
use core::ffi::c_void;
use core::ptr;
use std::collections::TryReserveError;

mod sealed {
    pub trait Sealed {}

    pub trait View {
        fn view(level: u32) -> Option<&'static Self>;
    }
}

/// The host at the base level, holding the level `GetWasmVersion`
/// reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credman {
    level: u32,
}

impl Credman {
    /// Reads the host level with [`GetWasmVersion`](credman::GetWasmVersion).
    pub(crate) fn connect() -> Self {
        let mut level = 0u32;
        // SAFETY: `level` is a live u32 the host writes once.
        unsafe { credman::GetWasmVersion(&mut level) };
        Self { level }
    }

    /// The level `GetWasmVersion` reported.
    pub const fn level(&self) -> u32 {
        self.level
    }

    /// The host at level `L`, when the reported level reaches it.
    pub fn version<L: Level>(&self) -> Option<&'static L> {
        L::view(self.level)
    }
}

impl sealed::Sealed for Credman {}
impl V1 for Credman {}

/// A level's singleton, [`Credman2`] to [`Credman7`], which
/// [`Credman::version`] grants.
pub trait Level: sealed::View {}

macro_rules! level {
    ($singleton:ident, $instance:ident, $level:literal, [$($trait:ident),+]) => {
        #[doc = concat!("The host at level ", $level, ", from [`Credman::version`].")]
        #[derive(Debug, PartialEq, Eq)]
        pub struct $singleton(());

        static $instance: $singleton = $singleton(());

        impl sealed::View for $singleton {
            fn view(level: u32) -> Option<&'static Self> {
                (level >= $level).then_some(&$instance)
            }
        }

        impl Level for $singleton {}
        impl sealed::Sealed for $singleton {}
        $(impl $trait for $singleton {})+
    };
}

level!(Credman2, CREDMAN2, 2, [V1, V2]);
level!(Credman3, CREDMAN3, 3, [V1, V2, V3]);
level!(Credman4, CREDMAN4, 4, [V1, V2, V3, V4]);
level!(Credman5, CREDMAN5, 5, [V1, V2, V3, V4, V5]);
level!(Credman6, CREDMAN6, 6, [V1, V2, V3, V4, V5, V6]);
level!(Credman7, CREDMAN7, 7, [V1, V2, V3, V4, V5, V6, V7]);

/// How the host names an entry in a set: the set, the position and the
/// entry's id. Fields and the calls of levels 5 to 7 attach by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryKey<'a> {
    /// Declared earlier by [`V2::add_entry_set`].
    pub set_id: &'a C8Str,
    /// Below the set's length.
    pub set_index: i32,
    /// Distinct among the alternatives of one position.
    pub cred_id: &'a C8Str,
}

/// The functions every host provides (module `credman`): the inputs, the
/// standalone entries a matcher adds below level 2, and the level probe.
pub trait V1: sealed::Sealed {
    /// The Digital Credentials API request as JSON, read with
    /// [`GetRequestSize`](credman::GetRequestSize) and
    /// [`GetRequestBuffer`](credman::GetRequestBuffer).
    ///
    /// # Errors
    ///
    /// [`TryReserveError`] when the reported length cannot be allocated.
    fn request(&self) -> Result<Vec<u8>, TryReserveError> {
        let mut size = 0u32;
        // SAFETY: `size` is a live u32 the host writes once.
        unsafe { credman::GetRequestSize(&mut size) };
        let mut request = Vec::new();
        request.try_reserve_exact(size as usize)?;
        request.resize(size as usize, 0);
        // SAFETY: the buffer holds the `size` bytes the host writes.
        unsafe { credman::GetRequestBuffer(request.as_mut_ptr().cast::<c_void>()) };
        Ok(request)
    }

    /// The length in bytes of the credential blob the wallet registered, from
    /// [`GetCredentialsSize`](credman::GetCredentialsSize).
    fn credentials_size(&self) -> usize {
        let mut size = 0u32;
        // SAFETY: `size` is a live u32 the host writes once.
        unsafe { credman::GetCredentialsSize(&mut size) };
        size as usize
    }

    /// Asks the host for the blob's bytes from `offset` into `buffer` with
    /// [`ReadCredentialsBuffer`](credman::ReadCredentialsBuffer), and returns
    /// the count it reports: at most `buffer.len()`, and 0 past the end.
    fn read_credentials_buffer(&self, buffer: &mut [u8], offset: usize) -> usize {
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

    /// The calling app as the host writes it, with
    /// [`GetCallingAppInfo`](credman::GetCallingAppInfo).
    fn calling_app_info(&self) -> CallingAppInfo {
        let mut info = CallingAppInfo::ZEROED;
        // SAFETY: `info` is a whole CallingAppInfo the host fills.
        unsafe { credman::GetCallingAppInfo(&mut info) };
        info
    }

    /// [`AddEntry`](credman::AddEntry): a standalone entry named by a number.
    fn add_entry(&self, cred_id: i64, display: &LegacyDisplay<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddEntry(
                cred_id,
                display.icon.as_ptr().cast(),
                display.icon.len(),
                display.title.as_ptr(),
                display.subtitle.as_ptr(),
                display.disclaimer.as_ptr(),
                display.warning.as_ptr(),
            );
        }
    }

    /// [`AddField`](credman::AddField): a field of the [`V1::add_entry`]
    /// entry with this `cred_id`.
    fn add_field(&self, cred_id: i64, field: &LegacyField<'_>) {
        // SAFETY: see the module documentation.
        unsafe { credman::AddField(cred_id, field.name.as_ptr(), field.value.as_ptr()) };
    }

    /// [`AddStringIdEntry`](credman::AddStringIdEntry): a standalone
    /// verification entry.
    fn add_string_id_entry(&self, cred_id: &C8Str, display: &VerificationDisplay<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddStringIdEntry(
                cred_id.as_ptr(),
                display.icon.as_ptr().cast(),
                display.icon.len(),
                display.title.as_ptr(),
                display.subtitle.map_or(ptr::null(), C8Str::as_ptr),
                display.disclaimer.map_or(ptr::null(), C8Str::as_ptr),
                display.warning.map_or(ptr::null(), C8Str::as_ptr),
            );
        }
    }

    /// [`AddFieldForStringIdEntry`](credman::AddFieldForStringIdEntry): a
    /// field of the [`V1::add_string_id_entry`] entry with this `cred_id`.
    fn add_field_for_string_id_entry(&self, cred_id: &C8Str, field: &Field<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddFieldForStringIdEntry(
                cred_id.as_ptr(),
                field.name.as_ptr(),
                field.value.map_or(ptr::null(), C8Str::as_ptr),
            );
        }
    }

    /// [`AddPaymentEntry`](credman::AddPaymentEntry): a standalone payment
    /// entry.
    fn add_payment_entry(&self, cred_id: &C8Str, display: &PaymentDisplay<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            credman::AddPaymentEntry(
                cred_id.as_ptr(),
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

    /// [`AddInlineIssuanceEntry`](credman::AddInlineIssuanceEntry): an entry
    /// that offers to issue a credential the wallet lacks.
    fn add_inline_issuance_entry(&self, entry: &InlineIssuanceEntry<'_>) {
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

    /// [`SetAdditionalDisclaimerAndUrlForVerificationEntry`](credman::SetAdditionalDisclaimerAndUrlForVerificationEntry):
    /// a link on the [`V1::add_string_id_entry`] entry with this `cred_id`.
    fn set_additional_disclaimer_and_url_for_verification_entry(
        &self,
        cred_id: &C8Str,
        link: &VerificationLink<'_>,
    ) {
        // SAFETY: see the module documentation.
        unsafe {
            credman::SetAdditionalDisclaimerAndUrlForVerificationEntry(
                cred_id.as_ptr(),
                link.secondary_disclaimer.as_ptr(),
                link.url_display_text.as_ptr(),
                link.url_value.as_ptr(),
            );
        }
    }
}

/// Level 2 (module `credman_v2`): entry sets.
pub trait V2: V1 {
    /// [`AddEntrySet`](v2::AddEntrySet): declares a set with `set_length`
    /// positions. A set id is declared once per invocation.
    fn add_entry_set(&self, set_id: &C8Str, set_length: i32) {
        // SAFETY: see the module documentation.
        unsafe { v2::AddEntrySet(set_id.as_ptr(), set_length) };
    }

    /// [`AddEntryToSet`](v2::AddEntryToSet): a verification entry at `key`.
    /// The host returns `metadata` to the wallet on selection.
    fn add_entry_to_set(
        &self,
        key: &EntryKey<'_>,
        display: &VerificationDisplay<'_>,
        metadata: Option<&C8Str>,
    ) {
        // SAFETY: see the module documentation.
        unsafe {
            v2::AddEntryToSet(
                key.cred_id.as_ptr(),
                display.icon.as_ptr().cast(),
                display.icon.len(),
                display.title.as_ptr(),
                display.subtitle.map_or(ptr::null(), C8Str::as_ptr),
                display.disclaimer.map_or(ptr::null(), C8Str::as_ptr),
                display.warning.map_or(ptr::null(), C8Str::as_ptr),
                metadata.map_or(ptr::null(), C8Str::as_ptr),
                key.set_id.as_ptr(),
                key.set_index,
            );
        }
    }

    /// [`AddFieldToEntrySet`](v2::AddFieldToEntrySet): a field of the entry
    /// at `key`.
    fn add_field_to_entry_set(&self, key: &EntryKey<'_>, field: &Field<'_>) {
        // SAFETY: see the module documentation.
        unsafe {
            v2::AddFieldToEntrySet(
                key.cred_id.as_ptr(),
                field.name.as_ptr(),
                field.value.map_or(ptr::null(), C8Str::as_ptr),
                key.set_id.as_ptr(),
                key.set_index,
            );
        }
    }

    /// [`AddPaymentEntryToSet`](v2::AddPaymentEntryToSet): a payment entry at
    /// `key`. The host returns `metadata` to the wallet on selection.
    fn add_payment_entry_to_set(
        &self,
        key: &EntryKey<'_>,
        display: &PaymentDisplay<'_>,
        metadata: Option<&C8Str>,
    ) {
        // SAFETY: see the module documentation.
        unsafe {
            v2::AddPaymentEntryToSet(
                key.cred_id.as_ptr(),
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
                metadata.map_or(ptr::null(), C8Str::as_ptr),
                key.set_id.as_ptr(),
                key.set_index,
            );
        }
    }
}

/// Level 3 (imported from `credman_v2`): payment entries with more text about
/// the transaction.
pub trait V3: V2 {
    /// [`AddPaymentEntryToSetV2`](v3::AddPaymentEntryToSetV2):
    /// [`V2::add_payment_entry_to_set`] with `additional_info`, which Google's
    /// matcher takes from the request's transaction data.
    fn add_payment_entry_to_set_v2(
        &self,
        key: &EntryKey<'_>,
        display: &PaymentDisplay<'_>,
        additional_info: Option<&C8Str>,
        metadata: Option<&C8Str>,
    ) {
        // SAFETY: see the module documentation.
        unsafe {
            v3::AddPaymentEntryToSetV2(
                key.cred_id.as_ptr(),
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
                additional_info.map_or(ptr::null(), C8Str::as_ptr),
                metadata.map_or(ptr::null(), C8Str::as_ptr),
                key.set_id.as_ptr(),
                key.set_index,
            );
        }
    }
}

/// Level 4 (module `credman_v4`).
pub trait V4: V3 {
    /// [`SelfDeclarePackageInfo`](v4::SelfDeclarePackageInfo): declares the
    /// wallet app's display name and icon. Google's header says it works for
    /// system apps only.
    fn self_declare_package_info(&self, info: &PackageInfo<'_>) {
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

/// Level 5 (module `credman_v5`).
pub trait V5: V4 {
    /// [`AddMetadataDisplayTextToEntrySet`](v5::AddMetadataDisplayTextToEntrySet):
    /// display text on the entry at `key`.
    fn add_metadata_display_text_to_entry_set(&self, key: &EntryKey<'_>, text: &C8Str) {
        // SAFETY: see the module documentation.
        unsafe {
            v5::AddMetadataDisplayTextToEntrySet(
                key.cred_id.as_ptr(),
                text.as_ptr(),
                key.set_id.as_ptr(),
                key.set_index,
            );
        }
    }
}

/// Level 6 (module `credman_v6`).
pub trait V6: V5 {
    /// [`SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet`](v6::SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet):
    /// a second disclaimer and a link on the entry at `key`.
    fn set_additional_disclaimer_and_url_for_verification_entry_in_credential_set(
        &self,
        key: &EntryKey<'_>,
        link: &VerificationLink<'_>,
    ) {
        // SAFETY: see the module documentation.
        unsafe {
            v6::SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(
                key.cred_id.as_ptr(),
                link.secondary_disclaimer.as_ptr(),
                link.url_display_text.as_ptr(),
                link.url_value.as_ptr(),
                key.set_id.as_ptr(),
                key.set_index,
            );
        }
    }
}

/// Level 7 (module `credman_v7`).
pub trait V7: V6 {
    /// [`SetDelegationTypeForEntryInSet`](v7::SetDelegationTypeForEntryInSet):
    /// how the wallet completes the request when the user picks the entry at
    /// `key`.
    fn set_delegation_type_for_entry_in_set(&self, key: &EntryKey<'_>, delegation: DelegationType) {
        // SAFETY: see the module documentation.
        unsafe {
            v7::SetDelegationTypeForEntryInSet(
                key.cred_id.as_ptr(),
                delegation as i32,
                key.set_id.as_ptr(),
                key.set_index,
            );
        }
    }
}
