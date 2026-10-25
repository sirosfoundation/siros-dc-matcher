//! Entry sets, the picker's options from host level 2. An [`EntrySet`] has at
//! least one slot and every slot at least one entry; positions and the
//! declared length follow from the slots. The entry kind is a type
//! parameter: a binary links the calls of the kinds it builds and no others.

use crate::entry::{Field, PaymentDisplay, VerificationDisplay, VerificationLink};
use crate::version::{V3, V5, V6};
use c8str::C8Str;

pub(crate) mod sealed {
    pub trait Sealed {
        /// The call that adds the entry.
        #[cfg(target_arch = "wasm32")]
        fn add_entry(&self, at: &crate::sets_on_host::Address<'_>, metadata: Option<&c8str::C8Str>);

        /// The calls between the entry and its fields.
        #[cfg(target_arch = "wasm32")]
        fn after_entry(&self, _at: &crate::sets_on_host::Address<'_>) {}

        /// The calls after the fields.
        #[cfg(target_arch = "wasm32")]
        fn after_fields(&self, _at: &crate::sets_on_host::Address<'_>) {}
    }
}

/// What a set entry shows, which selects the calls that add it:
/// [`AddEntryToSet`] for [`VerificationDisplay`], [`AddPaymentEntryToSet`] for
/// [`PaymentDisplay`], [`AddPaymentEntryToSetV2`] for [`PaymentWithInfo`].
/// [`AnyEntry`] mixes them; [`WithLink`] and [`WithMetadataDisplayText`] add a
/// level's call to any kind.
///
/// [`AddEntryToSet`]: android_credman_sys::v2::AddEntryToSet
/// [`AddPaymentEntryToSet`]: android_credman_sys::v2::AddPaymentEntryToSet
/// [`AddPaymentEntryToSetV2`]: android_credman_sys::v3::AddPaymentEntryToSetV2
pub trait EntryKind: Copy + sealed::Sealed {}

impl EntryKind for VerificationDisplay<'_> {}
impl EntryKind for PaymentDisplay<'_> {}
impl EntryKind for PaymentWithInfo<'_> {}
impl EntryKind for AnyEntry<'_> {}
impl<K: EntryKind> EntryKind for WithLink<'_, K> {}
impl<K: EntryKind> EntryKind for WithMetadataDisplayText<'_, K> {}

impl sealed::Sealed for VerificationDisplay<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_entry(&self, at: &crate::sets_on_host::Address<'_>, metadata: Option<&C8Str>) {
        crate::sets_on_host::verification(at, self, metadata);
    }
}

impl sealed::Sealed for PaymentDisplay<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_entry(&self, at: &crate::sets_on_host::Address<'_>, metadata: Option<&C8Str>) {
        crate::sets_on_host::payment(at, self, metadata);
    }
}

impl sealed::Sealed for PaymentWithInfo<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_entry(&self, at: &crate::sets_on_host::Address<'_>, metadata: Option<&C8Str>) {
        crate::sets_on_host::payment_with_info(at, self, metadata);
    }
}

impl sealed::Sealed for AnyEntry<'_> {
    #[cfg(target_arch = "wasm32")]
    fn add_entry(&self, at: &crate::sets_on_host::Address<'_>, metadata: Option<&C8Str>) {
        match self {
            Self::Verification(display) => display.add_entry(at, metadata),
            Self::Payment(display) => display.add_entry(at, metadata),
            Self::PaymentWithInfo(payment) => payment.add_entry(at, metadata),
        }
    }
}

impl<K: EntryKind> sealed::Sealed for WithLink<'_, K> {
    #[cfg(target_arch = "wasm32")]
    fn add_entry(&self, at: &crate::sets_on_host::Address<'_>, metadata: Option<&C8Str>) {
        self.kind.add_entry(at, metadata);
    }

    #[cfg(target_arch = "wasm32")]
    fn after_entry(&self, at: &crate::sets_on_host::Address<'_>) {
        self.kind.after_entry(at);
        crate::sets_on_host::link(at, &self.link);
    }

    #[cfg(target_arch = "wasm32")]
    fn after_fields(&self, at: &crate::sets_on_host::Address<'_>) {
        self.kind.after_fields(at);
    }
}

impl<K: EntryKind> sealed::Sealed for WithMetadataDisplayText<'_, K> {
    #[cfg(target_arch = "wasm32")]
    fn add_entry(&self, at: &crate::sets_on_host::Address<'_>, metadata: Option<&C8Str>) {
        self.kind.add_entry(at, metadata);
    }

    #[cfg(target_arch = "wasm32")]
    fn after_entry(&self, at: &crate::sets_on_host::Address<'_>) {
        self.kind.after_entry(at);
    }

    #[cfg(target_arch = "wasm32")]
    fn after_fields(&self, at: &crate::sets_on_host::Address<'_>) {
        self.kind.after_fields(at);
        crate::sets_on_host::metadata_display_text(at, self.text);
    }
}

/// A payment entry with more text about the transaction, sent by
/// [`AddPaymentEntryToSetV2`]. Level 3.
///
/// [`AddPaymentEntryToSetV2`]: android_credman_sys::v3::AddPaymentEntryToSetV2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentWithInfo<'a> {
    pub level: V3,
    pub display: PaymentDisplay<'a>,
    /// Text about the transaction, such as the request's transaction data
    /// carries. How the picker shows it is unconfirmed.
    pub additional_info: Option<&'a C8Str>,
}

/// An entry of any kind, for slots that mix verification and payment
/// entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnyEntry<'a> {
    Verification(VerificationDisplay<'a>),
    Payment(PaymentDisplay<'a>),
    PaymentWithInfo(PaymentWithInfo<'a>),
}

/// An entry of kind `K` with a second disclaimer and a link, sent with
/// [`SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet`] after
/// the entry and before its fields. Level 6.
///
/// [`SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet`]: android_credman_sys::v6::SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithLink<'a, K> {
    pub kind: K,
    pub level: V6,
    pub link: VerificationLink<'a>,
}

/// An entry of kind `K` with display text, sent with
/// [`AddMetadataDisplayTextToEntrySet`] after the entry's fields. Where the
/// picker shows it is unconfirmed. Level 5.
///
/// [`AddMetadataDisplayTextToEntrySet`]: android_credman_sys::v5::AddMetadataDisplayTextToEntrySet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WithMetadataDisplayText<'a, K> {
    pub kind: K,
    pub level: V5,
    pub text: &'a C8Str,
}

/// How the wallet completes the request when the user picks a set entry
/// (androidx `DelegationType`). [`HostOptions::delegation`] sets it for every
/// entry. A selected set whose entries mix types falls back to
/// [`Self::NoDelegation`].
///
/// [`HostOptions::delegation`]: crate::HostOptions::delegation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationType {
    /// The host launches the wallet's activity, which handles any user
    /// interaction (androidx `NONE`).
    NoDelegation = 0,
    /// Credential Manager keeps its own UI and calls the wallet's background
    /// fulfilment service, which must answer within a timeout while a loading
    /// indicator shows (androidx `FULL`). A wallet that uses it declares that
    /// service.
    Full = 1,
}

/// One entry in a slot of an [`EntrySet`]: a credential the user can pick
/// for that position, shown as kind `K`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetEntry<'a, K> {
    cred_id: &'a C8Str,
    kind: K,
    metadata: Option<&'a C8Str>,
    fields: &'a [Field<'a>],
}

impl<'a, K: EntryKind> SetEntry<'a, K> {
    /// `cred_id` comes back to the wallet when the user selects the entry.
    /// It is distinct among the alternatives of one slot; the fields and the
    /// level-5 to level-7 calls attach by it.
    pub const fn new(cred_id: &'a C8Str, kind: K) -> Self {
        Self {
            cred_id,
            kind,
            metadata: None,
            fields: &[],
        }
    }

    /// Text the host returns to the wallet with the id on selection.
    pub const fn with_metadata(mut self, metadata: &'a C8Str) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Rows naming the values the entry discloses, sent after the entry.
    pub const fn with_fields(mut self, fields: &'a [Field<'a>]) -> Self {
        self.fields = fields;
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

    /// The text the wallet receives with the id on selection.
    pub const fn metadata(&self) -> Option<&'a C8Str> {
        self.metadata
    }

    /// The rows sent after the entry.
    pub const fn fields(&self) -> &'a [Field<'a>] {
        self.fields
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
    /// Declares the set with [`AddEntrySet`], then sends each alternative:
    /// the entry, the host's delegation setting, its kind's calls before the
    /// fields, the fields, then its kind's calls after them.
    ///
    /// [`AddEntrySet`]: android_credman_sys::v2::AddEntrySet
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>);
}
