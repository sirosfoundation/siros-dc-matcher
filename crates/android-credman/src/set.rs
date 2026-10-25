//! Entry sets, the picker's options from host level 2. An [`EntrySet`] has at
//! least one slot and every slot at least one entry; positions and the
//! declared length follow from the slots. The entry kind is a type
//! parameter: a binary links the add calls of the kinds it builds and no
//! others.

use crate::entry::{DelegationType, Field, PaymentDisplay, VerificationDisplay, VerificationLink};
use crate::text::C8StringExt;
use c8str::{C8Str, C8String};

pub(crate) mod sealed {
    pub trait Sealed {
        /// Whether the kind carries text that a host at `level` does not
        /// show.
        fn skips_display(&self, level: u32) -> bool;

        /// Sends the call that adds the entry, with the host's best call for
        /// the kind.
        #[cfg(target_arch = "wasm32")]
        fn add(&self, host: &dyn crate::V2, key: &crate::EntryKey<'_>, metadata: &c8str::C8Str);
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
    fn add(&self, host: &dyn crate::V2, key: &crate::EntryKey<'_>, metadata: &C8Str) {
        host.add_entry_to_set(key, self, Some(metadata));
    }
}

impl sealed::Sealed for Payment<'_> {
    fn skips_display(&self, level: u32) -> bool {
        self.additional_info.is_some() && level < 3
    }

    #[cfg(target_arch = "wasm32")]
    fn add(&self, host: &dyn crate::V2, key: &crate::EntryKey<'_>, metadata: &C8Str) {
        match host.version::<dyn crate::V3>() {
            Some(host) => host.add_payment_entry_to_set_v2(
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
    fn add(&self, host: &dyn crate::V2, key: &crate::EntryKey<'_>, metadata: &C8Str) {
        match self {
            Self::Verification(display) => display.add(host, key, metadata),
            Self::Payment(payment) => payment.add(host, key, metadata),
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
    link: Option<VerificationLink<'a>>,
    metadata_display_text: Option<&'a C8Str>,
    delegation: Option<DelegationType>,
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
        self.link = Some(link);
        self
    }

    /// androidx's `metadataDisplayText`, shown from level 5.
    pub const fn with_metadata_display_text(mut self, text: &'a C8Str) -> Self {
        self.metadata_display_text = Some(text);
        self
    }

    /// The entry's delegation, sent from level 7 in place of the host
    /// default.
    pub const fn with_delegation(mut self, delegation: DelegationType) -> Self {
        self.delegation = Some(delegation);
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
        self.link
    }

    /// The display text.
    pub const fn metadata_display_text(&self) -> Option<&'a C8Str> {
        self.metadata_display_text
    }

    /// The entry's own delegation.
    pub const fn delegation(&self) -> Option<DelegationType> {
        self.delegation
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
