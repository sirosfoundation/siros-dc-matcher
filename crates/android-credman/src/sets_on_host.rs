use crate::entry::{PaymentDisplay, VerificationDisplay, VerificationLink};
use crate::set::{DelegationType, EntryKind, EntrySet, PaymentWithInfo, SetEntry, SetSink};
use crate::version::{V2, V7};
use android_credman_sys::{v2, v3, v5, v6, v7};
use c8str::C8Str;
use core::ptr;

/// The host's entry sets, from [`Host::entry_sets`](crate::Host::entry_sets).
/// Every entry they send carries the host's delegation setting.
#[derive(Debug, Clone, Copy)]
pub struct EntrySets {
    delegation: Option<Delegation>,
}

impl EntrySets {
    pub(crate) fn new(_level: V2, delegation: Option<Delegation>) -> Self {
        Self { delegation }
    }
}

/// A level-7 host's delegation setting. Only `Host::connect_with` builds one,
/// and the call goes through `send`, so a binary that never calls
/// `connect_with` links no `credman_v7` import.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Delegation {
    level: V7,
    kind: DelegationType,
    send: fn(V7, &Address<'_>, DelegationType),
}

impl Delegation {
    pub(crate) fn new(level: V7, kind: DelegationType) -> Self {
        Self {
            level,
            kind,
            send: delegation,
        }
    }

    fn send(&self, at: &Address<'_>) {
        (self.send)(self.level, at, self.kind);
    }
}

impl SetSink for EntrySets {
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>) {
        // A slot occupies more than 4 bytes and wasm32 addresses 4 GiB, so
        // no set holds more slots than an i32 counts: the cast and the
        // position counter below are exact.
        let length = set.slot_count() as i32;
        // SAFETY: see the module documentation of `host`.
        unsafe { v2::AddEntrySet(set.id().as_ptr(), length) };
        for (index, slot) in (0_i32..).zip(set.slots()) {
            for entry in slot.alternatives() {
                emit_entry(entry, set.id(), index, self.delegation);
            }
        }
    }
}

/// Public only to appear in the sealed trait.
pub struct Address<'a> {
    cred_id: &'a C8Str,
    set_id: &'a C8Str,
    index: i32,
}

/// The order Google's matchers use.
fn emit_entry<K: EntryKind>(
    entry: &SetEntry<'_, K>,
    set_id: &C8Str,
    index: i32,
    delegation: Option<Delegation>,
) {
    let at = Address {
        cred_id: entry.cred_id(),
        set_id,
        index,
    };
    entry.kind().add_entry(&at, entry.metadata());
    if let Some(delegation) = delegation {
        delegation.send(&at);
    }
    entry.kind().after_entry(&at);
    for field in entry.fields() {
        // SAFETY: see the module documentation of `host`.
        unsafe {
            v2::AddFieldToEntrySet(
                at.cred_id.as_ptr(),
                field.name.as_ptr(),
                field.value.map_or(ptr::null(), C8Str::as_ptr),
                at.set_id.as_ptr(),
                at.index,
            );
        }
    }
    entry.kind().after_fields(&at);
}

pub(crate) fn verification(
    at: &Address<'_>,
    display: &VerificationDisplay<'_>,
    metadata: Option<&C8Str>,
) {
    // SAFETY: see the module documentation of `host`.
    unsafe {
        v2::AddEntryToSet(
            at.cred_id.as_ptr(),
            display.icon.as_ptr().cast(),
            display.icon.len(),
            display.title.as_ptr(),
            display.subtitle.map_or(ptr::null(), C8Str::as_ptr),
            display.disclaimer.map_or(ptr::null(), C8Str::as_ptr),
            display.warning.map_or(ptr::null(), C8Str::as_ptr),
            metadata.map_or(ptr::null(), C8Str::as_ptr),
            at.set_id.as_ptr(),
            at.index,
        );
    }
}

pub(crate) fn payment(at: &Address<'_>, display: &PaymentDisplay<'_>, metadata: Option<&C8Str>) {
    // SAFETY: see the module documentation of `host`.
    unsafe {
        v2::AddPaymentEntryToSet(
            at.cred_id.as_ptr(),
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
            at.set_id.as_ptr(),
            at.index,
        );
    }
}

pub(crate) fn payment_with_info(
    at: &Address<'_>,
    entry: &PaymentWithInfo<'_>,
    metadata: Option<&C8Str>,
) {
    let display = &entry.display;
    // SAFETY: see the module documentation of `host`.
    unsafe {
        v3::AddPaymentEntryToSetV2(
            at.cred_id.as_ptr(),
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
            entry.additional_info.map_or(ptr::null(), C8Str::as_ptr),
            metadata.map_or(ptr::null(), C8Str::as_ptr),
            at.set_id.as_ptr(),
            at.index,
        );
    }
}

fn delegation(_level: V7, at: &Address<'_>, delegation: DelegationType) {
    // SAFETY: see the module documentation of `host`.
    unsafe {
        v7::SetDelegationTypeForEntryInSet(
            at.cred_id.as_ptr(),
            delegation as i32,
            at.set_id.as_ptr(),
            at.index,
        );
    }
}

pub(crate) fn link(at: &Address<'_>, link: &VerificationLink<'_>) {
    // SAFETY: see the module documentation of `host`.
    unsafe {
        v6::SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet(
            at.cred_id.as_ptr(),
            link.secondary_disclaimer.as_ptr(),
            link.url_display_text.as_ptr(),
            link.url_value.as_ptr(),
            at.set_id.as_ptr(),
            at.index,
        );
    }
}

pub(crate) fn metadata_display_text(at: &Address<'_>, text: &C8Str) {
    // SAFETY: see the module documentation of `host`.
    unsafe {
        v5::AddMetadataDisplayTextToEntrySet(
            at.cred_id.as_ptr(),
            text.as_ptr(),
            at.set_id.as_ptr(),
            at.index,
        );
    }
}
