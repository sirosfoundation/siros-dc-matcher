use crate::entry::{PaymentDisplay, VerificationDisplay};
use crate::host::{optional, PaymentParts, VerificationParts};
#[cfg(feature = "v3")]
use crate::set::PaymentWithInfo;
use crate::set::{EntryKind, EntrySet, SetEntry, SetSink};
use crate::version::V2;
use android_credman_sys::{c_char, credman_v2};
use c8str::C8Str;

impl SetSink for V2 {
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>) {
        let set_id = set.id().as_ptr();
        // A slot occupies more than 4 bytes and wasm32 addresses 4 GiB, so
        // no set holds more slots than an i32 counts: the cast and the
        // position counter below are exact.
        let length = set.slot_count() as i32;
        // SAFETY: `set_id` is a live C string.
        unsafe { credman_v2::AddEntrySet(set_id, length) };
        for (index, slot) in (0_i32..).zip(set.slots()) {
            for entry in slot.alternatives() {
                emit_entry(entry, set_id, index);
            }
        }
    }
}

/// Public only to appear in the sealed trait.
pub struct Address {
    cred_id: *const c_char,
    set_id: *const c_char,
    index: i32,
}

/// The order Google's matchers use.
fn emit_entry<K: EntryKind>(entry: &SetEntry<'_, K>, set_id: *const c_char, index: i32) {
    let at = Address {
        cred_id: entry.cred_id().as_ptr(),
        set_id,
        index,
    };
    entry.kind().add_to_set(&at, entry.metadata());
    decorate_before_fields(&at, entry);
    for field in entry.fields() {
        // SAFETY: see the module documentation of `host`.
        unsafe {
            credman_v2::AddFieldToEntrySet(
                at.cred_id,
                field.name.as_ptr(),
                optional(field.value),
                at.set_id,
                at.index,
            );
        }
    }
    decorate_after_fields(&at, entry);
}

pub(crate) fn verification(
    at: &Address,
    display: &VerificationDisplay<'_>,
    metadata: Option<&C8Str>,
) {
    let d = VerificationParts::of(display);
    // SAFETY: see the module documentation of `host`.
    unsafe {
        credman_v2::AddEntryToSet(
            at.cred_id,
            d.icon.0,
            d.icon.1,
            d.title,
            d.subtitle,
            d.disclaimer,
            d.warning,
            optional(metadata),
            at.set_id,
            at.index,
        );
    }
}

pub(crate) fn payment(at: &Address, display: &PaymentDisplay<'_>, metadata: Option<&C8Str>) {
    let p = PaymentParts::of(display);
    // SAFETY: see the module documentation of `host`.
    unsafe {
        credman_v2::AddPaymentEntryToSet(
            at.cred_id,
            p.merchant,
            p.method,
            p.method_subtitle,
            p.method_icon.0,
            p.method_icon.1,
            p.amount,
            p.bank_icon.0,
            p.bank_icon.1,
            p.provider_icon.0,
            p.provider_icon.1,
            optional(metadata),
            at.set_id,
            at.index,
        );
    }
}

#[cfg(feature = "v3")]
pub(crate) fn payment_with_info(
    at: &Address,
    entry: &PaymentWithInfo<'_>,
    metadata: Option<&C8Str>,
) {
    let p = PaymentParts::of(&entry.display);
    // SAFETY: see the module documentation of `host`.
    unsafe {
        android_credman_sys::credman_v3::AddPaymentEntryToSetV2(
            at.cred_id,
            p.merchant,
            p.method,
            p.method_subtitle,
            p.method_icon.0,
            p.method_icon.1,
            p.amount,
            p.bank_icon.0,
            p.bank_icon.1,
            p.provider_icon.0,
            p.provider_icon.1,
            optional(entry.additional_info),
            optional(metadata),
            at.set_id,
            at.index,
        );
    }
}

#[cfg_attr(not(any(feature = "v6", feature = "v7")), allow(unused_variables))]
fn decorate_before_fields<K: EntryKind>(at: &Address, entry: &SetEntry<'_, K>) {
    #[cfg(feature = "v7")]
    if let Some(delegation) = entry.delegation() {
        // SAFETY: see the module documentation of `host`.
        unsafe {
            android_credman_sys::credman_v7::SetDelegationTypeForEntryInSet(
                at.cred_id,
                delegation as i32,
                at.set_id,
                at.index,
            );
        }
    }
    #[cfg(feature = "v6")]
    if let Some(link) = entry.link() {
        // SAFETY: see the module documentation of `host`.
        unsafe {
            android_credman_sys::credman_v6::SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(
                at.cred_id,
                link.secondary_disclaimer.as_ptr(),
                link.url_display_text.as_ptr(),
                link.url_value.as_ptr(),
                at.set_id,
                at.index,
            );
        }
    }
}

#[cfg_attr(not(feature = "v5"), allow(unused_variables))]
fn decorate_after_fields<K: EntryKind>(at: &Address, entry: &SetEntry<'_, K>) {
    #[cfg(feature = "v5")]
    if let Some(text) = entry.metadata_display_text() {
        // SAFETY: see the module documentation of `host`.
        unsafe {
            android_credman_sys::credman_v5::AddMetadataDisplayTextToEntrySet(
                at.cred_id,
                text.as_ptr(),
                at.set_id,
                at.index,
            );
        }
    }
}
