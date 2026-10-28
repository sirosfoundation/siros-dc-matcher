//! Entry sets, the picker's options from host level 2. An [`EntrySet`] has at
//! least one slot and every slot at least one entry; positions and the
//! declared length follow from the slots. The entry kind is a type
//! parameter: a binary links the add calls of the kinds it builds and no
//! others.

use crate::entry::{DelegationType, Field, PaymentDisplay, VerificationDisplay, VerificationLink};
#[cfg(target_arch = "wasm32")]
use crate::levels::{
    Credman, Credman2, Credman3, Credman5, Credman6, Credman7, EntryKey, V2, V3, V5, V6, V7,
};
use crate::text::C8StringExt;
use c8str::{C8Str, C8String};
use core::fmt;

pub(crate) mod sealed {
    pub trait Sealed {
        /// Whether the kind carries text that a host at `level` does not
        /// show.
        fn skips_display(&self, level: u32) -> bool;

        /// Sends the call that adds the entry, with the host's best call for
        /// the kind.
        #[cfg(target_arch = "wasm32")]
        fn add(
            &self,
            base: &crate::levels::Credman,
            host: &crate::levels::Credman2,
            key: &crate::levels::EntryKey<'_>,
            metadata: &c8str::C8Str,
        );
    }
}

/// What a set entry shows, which selects the call that adds it:
/// [`AddEntryToSet`] for [`VerificationDisplay`], [`AddPaymentEntryToSetV2`]
/// or [`AddPaymentEntryToSet`] for [`Payment`]. [`AnyEntry`] mixes them.
///
/// [`AddEntryToSet`]: android_credman_sys::v2::AddEntryToSet
/// [`AddPaymentEntryToSet`]: android_credman_sys::v2::AddPaymentEntryToSet
/// [`AddPaymentEntryToSetV2`]: android_credman_sys::v3::AddPaymentEntryToSetV2
pub trait EntryKind: Copy + sealed::Sealed {}

impl EntryKind for VerificationDisplay<'_> {}
impl EntryKind for Payment<'_> {}
impl EntryKind for AnyEntry<'_> {}

impl sealed::Sealed for VerificationDisplay<'_> {
    fn skips_display(&self, _level: u32) -> bool {
        false
    }

    #[cfg(target_arch = "wasm32")]
    fn add(&self, _base: &Credman, host: &Credman2, key: &EntryKey<'_>, metadata: &C8Str) {
        host.add_entry_to_set(key, self, Some(metadata));
    }
}

impl sealed::Sealed for Payment<'_> {
    fn skips_display(&self, level: u32) -> bool {
        self.additional_info.is_some() && level < 3
    }

    #[cfg(target_arch = "wasm32")]
    fn add(&self, base: &Credman, host: &Credman2, key: &EntryKey<'_>, metadata: &C8Str) {
        match base.version::<Credman3>() {
            Some(level) => level.add_payment_entry_to_set_v2(
                key,
                &self.display,
                self.additional_info,
                Some(metadata),
            ),
            None => host.add_payment_entry_to_set(key, &self.display, Some(metadata)),
        }
    }
}

impl sealed::Sealed for AnyEntry<'_> {
    fn skips_display(&self, level: u32) -> bool {
        match self {
            Self::Verification(display) => display.skips_display(level),
            Self::Payment(payment) => payment.skips_display(level),
        }
    }

    #[cfg(target_arch = "wasm32")]
    fn add(&self, base: &Credman, host: &Credman2, key: &EntryKey<'_>, metadata: &C8Str) {
        match self {
            Self::Verification(display) => display.add(base, host, key, metadata),
            Self::Payment(payment) => payment.add(base, host, key, metadata),
        }
    }
}

/// A payment entry. From level 3 the host shows `additional_info`, more text
/// about the transaction that Google's matcher takes from the request's
/// transaction data; at level 2 it shows the display alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payment<'a> {
    pub display: PaymentDisplay<'a>,
    pub additional_info: Option<&'a C8Str>,
}

/// An entry of any kind, for slots that mix verification and payment
/// entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyEntry<'a> {
    Verification(VerificationDisplay<'a>),
    Payment(Payment<'a>),
}

/// One entry in a slot of an [`EntrySet`]: a credential the user can pick
/// for that position, shown as kind `K`. Each option is sent when the host
/// reaches its level and is not shown below it; the standard metadata object
/// tells the wallet whether text was left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetEntry<'a, K> {
    cred_id: &'a C8Str,
    kind: K,
    data: Option<&'a C8Str>,
    fields: &'a [Field<'a>],
    link: Option<Sent<VerificationLink<'a>>>,
    metadata_display_text: Option<Sent<&'a C8Str>>,
    delegation: Option<Sent<DelegationType>>,
}

impl<'a, K: EntryKind> SetEntry<'a, K> {
    /// `cred_id` comes back to the wallet when the user selects the entry.
    /// It is distinct among the alternatives of one slot; the fields and the
    /// options attach by it.
    pub const fn new(cred_id: &'a C8Str, kind: K) -> Self {
        Self {
            cred_id,
            kind,
            data: None,
            fields: &[],
            link: None,
            metadata_display_text: None,
            delegation: None,
        }
    }

    /// The caller's JSON value, which the wallet receives as `data` in the
    /// standard metadata object.
    pub const fn with_data(mut self, json: &'a C8Str) -> Self {
        self.data = Some(json);
        self
    }

    /// Rows naming the values the entry discloses.
    pub const fn with_fields(mut self, fields: &'a [Field<'a>]) -> Self {
        self.fields = fields;
        self
    }

    /// A second disclaimer and a link, shown from level 6.
    pub const fn with_link(mut self, link: VerificationLink<'a>) -> Self {
        self.link = Some(Sent::link(link));
        self
    }

    /// androidx's `metadataDisplayText`, shown from level 5.
    pub const fn with_metadata_display_text(mut self, text: &'a C8Str) -> Self {
        self.metadata_display_text = Some(Sent::metadata_display_text(text));
        self
    }

    /// The entry's delegation, sent from level 7 in place of the host
    /// default.
    pub const fn with_delegation(mut self, delegation: DelegationType) -> Self {
        self.delegation = Some(Sent::delegation(delegation));
        self
    }

    /// The id the wallet receives on selection.
    pub const fn cred_id(&self) -> &'a C8Str {
        self.cred_id
    }

    /// What the entry shows.
    pub const fn kind(&self) -> &K {
        &self.kind
    }

    /// The caller's JSON value.
    pub const fn data(&self) -> Option<&'a C8Str> {
        self.data
    }

    /// The rows sent after the entry.
    pub const fn fields(&self) -> &'a [Field<'a>] {
        self.fields
    }

    /// The second disclaimer and link.
    pub const fn link(&self) -> Option<VerificationLink<'a>> {
        match self.link {
            Some(link) => Some(link.value),
            None => None,
        }
    }

    /// The display text.
    pub const fn metadata_display_text(&self) -> Option<&'a C8Str> {
        match self.metadata_display_text {
            Some(text) => Some(text.value),
            None => None,
        }
    }

    /// The entry's own delegation.
    pub const fn delegation(&self) -> Option<DelegationType> {
        match self.delegation {
            Some(delegation) => Some(delegation.value),
            None => None,
        }
    }

    /// Whether the entry carries text that a host at `level` does not show:
    /// payment information below level 3, display text below level 5, a link
    /// below level 6.
    pub fn display_skipped(&self, level: u32) -> bool {
        self.kind.skips_display(level)
            || (self.metadata_display_text.is_some() && level < 5)
            || (self.link.is_some() && level < 6)
    }

    /// The standard metadata object, which the host returns to the wallet with
    /// the id on selection:
    /// `{"display_skipped":bool,"host_level":n,"data":<the caller's JSON>}`,
    /// without `data` when the caller sets none.
    pub fn metadata(&self, level: u32) -> C8String {
        let mut object = C8String::from_str_lossy(&format!(
            "{{\"display_skipped\":{},\"host_level\":{level}",
            self.display_skipped(level)
        ));
        if let Some(data) = self.data {
            object.push_str_lossy(",\"data\":");
            object.push_c8_str(data);
        }
        object.push_str_lossy("}");
        object
    }
}

#[cfg(target_arch = "wasm32")]
impl<K: EntryKind> SetEntry<'_, K> {
    /// Sends the entry at `key` in the order of Google's matchers: the add
    /// call with the standard metadata object, the delegation (the entry's
    /// own, else `default`), the link, the fields, the display text.
    pub(crate) fn send(
        &self,
        base: &Credman,
        host: &Credman2,
        key: &EntryKey<'_>,
        default: Option<Sent<DelegationType>>,
    ) {
        self.kind.add(base, host, key, &self.metadata(base.level()));
        if let Some(delegation) = self.delegation.or(default) {
            (delegation.send)(base, key, &delegation.value);
        }
        if let Some(link) = self.link {
            (link.send)(base, key, &link.value);
        }
        for field in self.fields {
            host.add_field_to_entry_set(key, field);
        }
        if let Some(text) = self.metadata_display_text {
            (text.send)(base, key, &text.value);
        }
    }
}

/// One position of an [`EntrySet`]: the alternatives the user chooses
/// between, such as the credentials that answer one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot<'a, K> {
    first: &'a SetEntry<'a, K>,
    others: &'a [SetEntry<'a, K>],
}

impl<'a, K: EntryKind> Slot<'a, K> {
    /// A position with one entry.
    pub const fn one(entry: &'a SetEntry<'a, K>) -> Self {
        Self {
            first: entry,
            others: &[],
        }
    }

    /// A position with `first` and the further alternatives `others`.
    pub const fn with_alternatives(
        first: &'a SetEntry<'a, K>,
        others: &'a [SetEntry<'a, K>],
    ) -> Self {
        Self { first, others }
    }

    /// The entries, `first` first.
    pub fn alternatives(&self) -> impl Iterator<Item = &'a SetEntry<'a, K>> {
        core::iter::once(self.first).chain(self.others)
    }
}

/// One option in the picker, which the user selects whole, picking one
/// alternative in each slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrySet<'a, K> {
    id: &'a C8Str,
    first: Slot<'a, K>,
    others: &'a [Slot<'a, K>],
}

impl<'a, K: EntryKind> EntrySet<'a, K> {
    /// `id` comes back to the wallet when the user selects the set. Declare
    /// it once per invocation: the host discards everything the matcher added
    /// when one id is declared twice. The slots are `first`, then `others`,
    /// in position order.
    pub const fn new(id: &'a C8Str, first: Slot<'a, K>, others: &'a [Slot<'a, K>]) -> Self {
        Self { id, first, others }
    }

    /// The id the wallet receives on selection.
    pub const fn id(&self) -> &'a C8Str {
        self.id
    }

    /// The number of positions, which the declaration sends as the set's
    /// length.
    pub const fn slot_count(&self) -> usize {
        1 + self.others.len()
    }

    /// The slots in position order.
    pub fn slots(&self) -> impl Iterator<Item = &Slot<'a, K>> {
        core::iter::once(&self.first).chain(self.others)
    }
}

/// Where a matcher sends its entry sets: [`crate::EntrySets`] sends them to
/// the host, and a test implements it to record them.
pub trait SetSink {
    /// Declares the set with [`AddEntrySet`], then sends each alternative in
    /// the order of Google's matchers: the entry with its
    /// [`SetEntry::metadata`], its delegation (its own, else the host
    /// default), its link, its fields, its display text. An option above the
    /// host's level is not sent.
    ///
    /// [`AddEntrySet`]: android_credman_sys::v2::AddEntrySet
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>);
}

/// An option and the call that sends it. Only the builder that sets the
/// option reaches the call, so a binary that never sets it imports nothing
/// for it.
#[derive(Clone, Copy)]
pub(crate) struct Sent<T> {
    pub(crate) value: T,
    #[cfg(target_arch = "wasm32")]
    pub(crate) send: fn(&Credman, &EntryKey<'_>, &T),
}

impl Sent<DelegationType> {
    pub(crate) const fn delegation(value: DelegationType) -> Self {
        Self {
            value,
            #[cfg(target_arch = "wasm32")]
            send: send_delegation,
        }
    }
}

impl<'a> Sent<VerificationLink<'a>> {
    const fn link(value: VerificationLink<'a>) -> Self {
        Self {
            value,
            #[cfg(target_arch = "wasm32")]
            send: send_link,
        }
    }
}

impl<'a> Sent<&'a C8Str> {
    const fn metadata_display_text(value: &'a C8Str) -> Self {
        Self {
            value,
            #[cfg(target_arch = "wasm32")]
            send: send_metadata_display_text,
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn send_delegation(base: &Credman, key: &EntryKey<'_>, delegation: &DelegationType) {
    if let Some(host) = base.version::<Credman7>() {
        host.set_delegation_type_for_entry_in_set(key, *delegation);
    }
}

#[cfg(target_arch = "wasm32")]
fn send_link(base: &Credman, key: &EntryKey<'_>, link: &VerificationLink<'_>) {
    if let Some(host) = base.version::<Credman6>() {
        host.set_additional_disclaimer_and_url_for_verification_entry_in_credential_set(key, link);
    }
}

#[cfg(target_arch = "wasm32")]
fn send_metadata_display_text(base: &Credman, key: &EntryKey<'_>, text: &&C8Str) {
    if let Some(host) = base.version::<Credman5>() {
        host.add_metadata_display_text_to_entry_set(key, text);
    }
}

impl<T: fmt::Debug> fmt::Debug for Sent<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T: PartialEq> PartialEq for Sent<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq> Eq for Sent<T> {}
