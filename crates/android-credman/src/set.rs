//! An [`EntrySet`] has at least one slot and every slot at least one entry;
//! positions and the declared length follow from the slots. The entry kind
//! is a type parameter, so a matcher that builds only
//! [`VerificationDisplay`] entries links no payment function.

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
    pub trait Sealed {
        #[cfg(all(target_arch = "wasm32", feature = "v2"))]
        fn add_to_set(&self, at: &crate::sets_on_host::Address, metadata: Option<&c8str::C8Str>);
    }
}

/// Selects the function that adds the entry: `AddEntryToSet` for
/// [`VerificationDisplay`], `AddPaymentEntryToSet` for [`PaymentDisplay`],
/// `AddPaymentEntryToSetV2` for [`PaymentWithInfo`]. [`AnyEntry`] mixes them.
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

#[cfg(feature = "v3")]
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
    #[cfg(feature = "v3")]
    PaymentWithInfo(PaymentWithInfo<'a>),
}

/// androidx's `DelegationType` values.
#[cfg(feature = "v7")]
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
    #[cfg(feature = "v7")]
    delegation: Option<(V7, DelegationType)>,
    #[cfg(feature = "v6")]
    link: Option<(V6, VerificationLink<'a>)>,
    #[cfg(feature = "v5")]
    metadata_display_text: Option<(V5, &'a C8Str)>,
}

impl<'a, K: EntryKind> SetEntry<'a, K> {
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

    /// Returned to the wallet on selection.
    pub const fn with_metadata(mut self, metadata: &'a C8Str) -> Self {
        self.metadata = Some(metadata);
        self
    }

    pub const fn with_fields(mut self, fields: &'a [Field<'a>]) -> Self {
        self.fields = fields;
        self
    }

    #[cfg(feature = "v7")]
    pub const fn with_delegation(mut self, level: V7, delegation: DelegationType) -> Self {
        self.delegation = Some((level, delegation));
        self
    }

    #[cfg(feature = "v6")]
    pub const fn with_link(mut self, level: V6, link: VerificationLink<'a>) -> Self {
        self.link = Some((level, link));
        self
    }

    #[cfg(feature = "v5")]
    pub const fn with_metadata_display_text(mut self, level: V5, text: &'a C8Str) -> Self {
        self.metadata_display_text = Some((level, text));
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

    #[cfg(feature = "v7")]
    pub fn delegation(&self) -> Option<DelegationType> {
        self.delegation.map(|(_, delegation)| delegation)
    }

    #[cfg(feature = "v6")]
    pub fn link(&self) -> Option<VerificationLink<'a>> {
        self.link.map(|(_, link)| link)
    }

    #[cfg(feature = "v5")]
    pub fn metadata_display_text(&self) -> Option<&'a C8Str> {
        self.metadata_display_text.map(|(_, text)| text)
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
    /// Sends the declaration, then each alternative followed by its
    /// delegation, link, fields and metadata display text.
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>);
}
