//! An [`EntrySet`] has at least one slot and every slot at least one entry;
//! positions and the declared length follow from the slots. The entry kind
//! is a type parameter: a binary links the calls of the kinds it builds and
//! no others.

use crate::entry::{Field, PaymentDisplay, VerificationDisplay, VerificationLink};
use crate::version::{V3, V5, V6, V7};
use c8str::C8Str;

pub(crate) mod sealed {
    pub trait Sealed {
        #[cfg(target_arch = "wasm32")]
        fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&c8str::C8Str>);

        #[cfg(target_arch = "wasm32")]
        fn after_fields(&self, _at: &crate::sets_on_host::Address) {}
    }
}

/// Selects the calls that add the entry: `AddEntryToSet` for
/// [`VerificationDisplay`], `AddPaymentEntryToSet` for [`PaymentDisplay`],
/// `AddPaymentEntryToSetV2` for [`PaymentWithInfo`]. [`AnyEntry`] mixes them;
/// [`WithDelegation`], [`WithLink`] and [`WithMetadataDisplayText`] add a
/// level's call to any kind.
pub trait EntryKind: Copy + sealed::Sealed {}

impl EntryKind for VerificationDisplay<'_> {}
impl EntryKind for PaymentDisplay<'_> {}
impl EntryKind for PaymentWithInfo<'_> {}
impl EntryKind for AnyEntry<'_> {}
impl<K: EntryKind> EntryKind for WithDelegation<K> {}
impl<K: EntryKind> EntryKind for WithLink<'_, K> {}
impl<K: EntryKind> EntryKind for WithMetadataDisplayText<'_, K> {}

impl sealed::Sealed for VerificationDisplay<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        crate::sets_on_host::verification(at, self, metadata);
    }
}

impl sealed::Sealed for PaymentDisplay<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        crate::sets_on_host::payment(at, self, metadata);
    }
}

impl sealed::Sealed for PaymentWithInfo<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        crate::sets_on_host::payment_with_info(at, self, metadata);
    }
}

impl sealed::Sealed for AnyEntry<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        match self {
            Self::Verification(display) => display.add_to_set(at, metadata),
            Self::Payment(display) => display.add_to_set(at, metadata),
            Self::PaymentWithInfo(payment) => payment.add_to_set(at, metadata),
        }
    }
}

impl<K: EntryKind> sealed::Sealed for WithDelegation<K> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        self.kind.add_to_set(at, metadata);
        crate::sets_on_host::delegation(at, self.delegation);
    }

    #[cfg(target_arch = "wasm32")]
    fn after_fields(&self, at: &crate::sets_on_host::Address) {
        self.kind.after_fields(at);
    }
}

impl<K: EntryKind> sealed::Sealed for WithLink<'_, K> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        self.kind.add_to_set(at, metadata);
        crate::sets_on_host::link(at, &self.link);
    }

    #[cfg(target_arch = "wasm32")]
    fn after_fields(&self, at: &crate::sets_on_host::Address) {
        self.kind.after_fields(at);
    }
}

impl<K: EntryKind> sealed::Sealed for WithMetadataDisplayText<'_, K> {
    #[cfg(target_arch = "wasm32")]
    fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&C8Str>) {
        self.kind.add_to_set(at, metadata);
    }

    #[cfg(target_arch = "wasm32")]
    fn after_fields(&self, at: &crate::sets_on_host::Address) {
        self.kind.after_fields(at);
        crate::sets_on_host::metadata_display_text(at, self.text);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentWithInfo<'a> {
    pub level: V3,
    pub display: PaymentDisplay<'a>,
    pub additional_info: Option<&'a C8Str>,
}

/// For slots that mix kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyEntry<'a> {
    Verification(VerificationDisplay<'a>),
    Payment(PaymentDisplay<'a>),
    PaymentWithInfo(PaymentWithInfo<'a>),
}

/// `SetDelegationTypeForEntryInSet`, sent right after the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithDelegation<K> {
    pub kind: K,
    pub level: V7,
    pub delegation: DelegationType,
}

/// The level-6 link, sent right after the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithLink<'a, K> {
    pub kind: K,
    pub level: V6,
    pub link: VerificationLink<'a>,
}

/// `AddMetadataDisplayTextToEntrySet`, sent after the fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithMetadataDisplayText<'a, K> {
    pub kind: K,
    pub level: V5,
    pub text: &'a C8Str,
}

/// androidx's `DelegationType` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationType {
    /// The wallet's UI handles the selection.
    NoDelegation = 0,
    /// The wallet's background service fulfils it.
    Full = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetEntry<'a, K> {
    cred_id: &'a C8Str,
    kind: K,
    metadata: Option<&'a C8Str>,
    fields: &'a [Field<'a>],
}

impl<'a, K: EntryKind> SetEntry<'a, K> {
    pub const fn new(cred_id: &'a C8Str, kind: K) -> Self {
        Self {
            cred_id,
            kind,
            metadata: None,
            fields: &[],
        }
    }

    /// Returned to the wallet on selection.
    pub const fn with_metadata(mut self, metadata: &'a C8Str) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub const fn with_fields(mut self, fields: &'a [Field<'a>]) -> Self {
        self.fields = fields;
        self
    }

    pub const fn cred_id(&self) -> &'a C8Str {
        self.cred_id
    }

    pub const fn kind(&self) -> &K {
        &self.kind
    }

    pub const fn metadata(&self) -> Option<&'a C8Str> {
        self.metadata
    }

    pub const fn fields(&self) -> &'a [Field<'a>] {
        self.fields
    }
}

/// The user picks one alternative per slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot<'a, K> {
    first: &'a SetEntry<'a, K>,
    others: &'a [SetEntry<'a, K>],
}

impl<'a, K: EntryKind> Slot<'a, K> {
    pub const fn one(entry: &'a SetEntry<'a, K>) -> Self {
        Self {
            first: entry,
            others: &[],
        }
    }

    pub const fn with_alternatives(
        first: &'a SetEntry<'a, K>,
        others: &'a [SetEntry<'a, K>],
    ) -> Self {
        Self { first, others }
    }

    pub fn alternatives(&self) -> impl Iterator<Item = &'a SetEntry<'a, K>> {
        core::iter::once(self.first).chain(self.others)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntrySet<'a, K> {
    id: &'a C8Str,
    first: Slot<'a, K>,
    others: &'a [Slot<'a, K>],
}

impl<'a, K: EntryKind> EntrySet<'a, K> {
    pub const fn new(id: &'a C8Str, first: Slot<'a, K>, others: &'a [Slot<'a, K>]) -> Self {
        Self { id, first, others }
    }

    pub const fn id(&self) -> &'a C8Str {
        self.id
    }

    pub const fn slot_count(&self) -> usize {
        1 + self.others.len()
    }

    pub fn slots(&self) -> impl Iterator<Item = &Slot<'a, K>> {
        core::iter::once(&self.first).chain(self.others)
    }
}

/// Implemented by `V2` on the host, and by a stand-in in a test.
pub trait SetSink {
    /// Sends the declaration, then each alternative: its kind's calls up to
    /// the fields, the fields, then its kind's calls after them.
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>);
}
