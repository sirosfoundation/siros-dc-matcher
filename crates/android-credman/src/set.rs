//! Entry sets (`credman_v2`) as values whose shape is the set contract.
//!
//! A set is one option the user selects as a whole. It has positions
//! ("slots") numbered from 0; each slot holds one or more alternatives, of
//! which the user picks one. In an [`EntrySet`] the declared length is the
//! number of slots, every slot holds at least one entry, positions follow
//! the slot order, and fields and decorations belong to their entry.
//!
//! Two rules stay with the caller, because a type cannot hold them: a set id
//! is declared once per invocation (the host discards everything when one
//! repeats), and the alternatives of one slot have distinct ids (the host
//! names an entry by set, position and id).
//!
//! The kind of entry is a type parameter. A matcher that builds only
//! verification entries links only `AddEntryToSet`; [`AnyEntry`] mixes kinds
//! in one set and links the functions of every kind.

#[cfg(feature = "v6")]
use crate::entry::VerificationLink;
use crate::entry::{Field, PaymentDisplay, VerificationDisplay};
#[cfg(feature = "v3")]
use crate::version::V3;
#[cfg(feature = "v5")]
use crate::version::V5;
#[cfg(feature = "v6")]
use crate::version::V6;
#[cfg(feature = "v7")]
use crate::version::V7;
use c8str::C8Str;

pub(crate) mod sealed {
    /// Implemented by the entry kinds of this crate alone.
    pub trait Sealed {
        /// Adds the entry with this display at `at`.
        #[cfg(all(target_arch = "wasm32", feature = "v2"))]
        fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&c8str::C8Str>);
    }
}

/// What a set entry shows, and so which `credman_v2` function adds it:
/// [`VerificationDisplay`] (`AddEntryToSet`), [`PaymentDisplay`]
/// (`AddPaymentEntryToSet`), [`PaymentWithInfo`] (`AddPaymentEntryToSetV2`)
/// or [`AnyEntry`].
pub trait EntryKind: Copy + sealed::Sealed {}

impl EntryKind for VerificationDisplay<'_> {}
impl EntryKind for PaymentDisplay<'_> {}
impl EntryKind for AnyEntry<'_> {}
#[cfg(feature = "v3")]
impl EntryKind for PaymentWithInfo<'_> {}

impl sealed::Sealed for VerificationDisplay<'_> {
    #[cfg(all(target_arch = "wasm32", feature = "v2"))]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        crate::sets_on_host::verification(at, self, metadata);
    }
}

impl sealed::Sealed for PaymentDisplay<'_> {
    #[cfg(all(target_arch = "wasm32", feature = "v2"))]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        crate::sets_on_host::payment(at, self, metadata);
    }
}

#[cfg(feature = "v3")]
impl sealed::Sealed for PaymentWithInfo<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        crate::sets_on_host::payment_with_info(at, self, metadata);
    }
}

impl sealed::Sealed for AnyEntry<'_> {
    #[cfg(all(target_arch = "wasm32", feature = "v2"))]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        match self {
            Self::Verification(display) => display.add_to_set(at, metadata),
            Self::Payment(display) => display.add_to_set(at, metadata),
            #[cfg(feature = "v3")]
            Self::PaymentWithInfo(payment) => payment.add_to_set(at, metadata),
        }
    }
}

/// A payment with extra text (`AddPaymentEntryToSetV2`, level 3).
#[cfg(feature = "v3")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentWithInfo<'a> {
    /// Proof the host has the function.
    pub level: V3,
    /// What the entry shows.
    pub display: PaymentDisplay<'a>,
    /// The extra text; `None` omits it.
    pub additional_info: Option<&'a C8Str>,
}

/// An entry of any kind, for slots that mix them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyEntry<'a> {
    /// A credential to present.
    Verification(VerificationDisplay<'a>),
    /// A payment.
    Payment(PaymentDisplay<'a>),
    /// A payment with extra text.
    #[cfg(feature = "v3")]
    PaymentWithInfo(PaymentWithInfo<'a>),
}

/// How the host fulfils a selected entry (`SetDelegationTypeForEntryInSet`).
///
/// The values are androidx's `DelegationType.NONE` and `DelegationType.FULL`.
#[cfg(feature = "v7")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationType {
    /// The wallet's own UI handles the selection.
    NoDelegation = 0,
    /// The wallet's background service fulfils it while Credential Manager
    /// shows its own UI.
    Full = 1,
}

/// One alternative in a slot of an [`EntrySet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetEntry<'a, K> {
    cred_id: &'a C8Str,
    kind: K,
    metadata: Option<&'a C8Str>,
    fields: &'a [Field<'a>],
    #[cfg(feature = "v7")]
    delegation: Option<(V7, DelegationType)>,
    #[cfg(feature = "v6")]
    link: Option<(V6, VerificationLink<'a>)>,
    #[cfg(feature = "v5")]
    metadata_display_text: Option<(V5, &'a C8Str)>,
}

impl<'a, K: EntryKind> SetEntry<'a, K> {
    /// An entry with no metadata, fields or decorations.
    pub const fn new(cred_id: &'a C8Str, kind: K) -> Self {
        Self {
            cred_id,
            kind,
            metadata: None,
            fields: &[],
            #[cfg(feature = "v7")]
            delegation: None,
            #[cfg(feature = "v6")]
            link: None,
            #[cfg(feature = "v5")]
            metadata_display_text: None,
        }
    }

    /// Text the host returns to the wallet when the user picks the entry.
    pub const fn with_metadata(mut self, metadata: &'a C8Str) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Display fields (`AddFieldToEntrySet`), in order.
    pub const fn with_fields(mut self, fields: &'a [Field<'a>]) -> Self {
        self.fields = fields;
        self
    }

    /// How the host fulfils the entry, sent right after it.
    #[cfg(feature = "v7")]
    pub const fn with_delegation(mut self, level: V7, delegation: DelegationType) -> Self {
        self.delegation = Some((level, delegation));
        self
    }

    /// A second disclaimer and a link, sent after the delegation.
    #[cfg(feature = "v6")]
    pub const fn with_link(mut self, level: V6, link: VerificationLink<'a>) -> Self {
        self.link = Some((level, link));
        self
    }

    /// A line of metadata text, sent after the fields.
    #[cfg(feature = "v5")]
    pub const fn with_metadata_display_text(mut self, level: V5, text: &'a C8Str) -> Self {
        self.metadata_display_text = Some((level, text));
        self
    }

    /// The id the wallet receives when the user picks this entry.
    pub const fn cred_id(&self) -> &'a C8Str {
        self.cred_id
    }

    /// What the entry shows.
    pub const fn kind(&self) -> &K {
        &self.kind
    }

    /// The selection metadata.
    pub const fn metadata(&self) -> Option<&'a C8Str> {
        self.metadata
    }

    /// The display fields.
    pub const fn fields(&self) -> &'a [Field<'a>] {
        self.fields
    }

    /// The delegation, when set.
    #[cfg(feature = "v7")]
    pub fn delegation(&self) -> Option<DelegationType> {
        self.delegation.map(|(_, delegation)| delegation)
    }

    /// The verification link, when set.
    #[cfg(feature = "v6")]
    pub fn link(&self) -> Option<VerificationLink<'a>> {
        self.link.map(|(_, link)| link)
    }

    /// The metadata display text, when set.
    #[cfg(feature = "v5")]
    pub fn metadata_display_text(&self) -> Option<&'a C8Str> {
        self.metadata_display_text.map(|(_, text)| text)
    }
}

/// One position of an [`EntrySet`]: a first entry and any further
/// alternatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot<'a, K> {
    first: &'a SetEntry<'a, K>,
    others: &'a [SetEntry<'a, K>],
}

impl<'a, K: EntryKind> Slot<'a, K> {
    /// A slot holding one entry.
    pub const fn one(entry: &'a SetEntry<'a, K>) -> Self {
        Self {
            first: entry,
            others: &[],
        }
    }

    /// A slot offering `first` and `others`, of which the user picks one.
    pub const fn with_alternatives(
        first: &'a SetEntry<'a, K>,
        others: &'a [SetEntry<'a, K>],
    ) -> Self {
        Self { first, others }
    }

    /// The alternatives, in emission order.
    pub fn alternatives(&self) -> impl Iterator<Item = &'a SetEntry<'a, K>> {
        core::iter::once(self.first).chain(self.others)
    }
}

/// A set ready for the host: its id and at least one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrySet<'a, K> {
    id: &'a C8Str,
    first: Slot<'a, K>,
    others: &'a [Slot<'a, K>],
}

impl<'a, K: EntryKind> EntrySet<'a, K> {
    /// A set declared under `id`, with `first` at position 0 and `others`
    /// after it.
    pub const fn new(id: &'a C8Str, first: Slot<'a, K>, others: &'a [Slot<'a, K>]) -> Self {
        Self { id, first, others }
    }

    /// The set id.
    pub const fn id(&self) -> &'a C8Str {
        self.id
    }

    /// The number of slots, as `AddEntrySet` declares it.
    pub const fn slot_count(&self) -> usize {
        1 + self.others.len()
    }

    /// The slots, in position order.
    pub fn slots(&self) -> impl Iterator<Item = &Slot<'a, K>> {
        core::iter::once(&self.first).chain(self.others)
    }
}

/// Where entry sets go: the host on a device, or a stand-in in a test.
pub trait SetSink {
    /// Emits `set`: its declaration, then each slot's alternatives in order,
    /// each followed by its delegation, link, fields and metadata display
    /// text.
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>);
}
