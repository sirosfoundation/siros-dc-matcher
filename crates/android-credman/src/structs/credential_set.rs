use crate::{CredentialEntry, CredentialSlot, CredmanApply, CredmanContext, CredmanSetContext};
use core::ffi::CStr;
use std::borrow::Cow;

/// A visual group (Set) of credentials.
///
/// In Android Credential Manager, a Set is a top-level item that expands.
/// Each item in the set (a "slot") can contain multiple alternatives.
///
/// # Semantics
/// - `CredentialSet` is an OR-select across its slots.
/// - Each slot is an OR-select across its alternatives.
/// - On hosts without set support (v1), entries are emitted as standalone rows.
#[derive(Debug, Clone)]
pub struct CredentialSet<'a> {
    pub set_id: Cow<'a, CStr>,
    pub slots: Cow<'a, [CredentialSlot<'a>]>,
}

impl<'a> CredentialSet<'a> {
    pub fn new(set_id: &'a CStr) -> Self {
        Self::new_cow(Cow::Borrowed(set_id))
    }

    pub fn new_cow(set_id: Cow<'a, CStr>) -> Self {
        Self {
            set_id,
            slots: Cow::Borrowed(&[]),
        }
    }

    /// Adds a slot to the set.
    pub fn add_slot<S: Into<CredentialSlot<'a>>>(mut self, slot: S) -> Self {
        let mut slots = self.slots.into_owned();
        slots.push(slot.into());
        self.slots = Cow::Owned(slots);
        self
    }

    /// Shortcut to add a single entry to the set as its own slot.
    pub fn add_entry(self, entry: CredentialEntry<'a>) -> Self {
        self.add_slot(entry)
    }

    /// Adds multiple entries, each as its own slot.
    pub fn add_entries<I>(mut self, entries: I) -> Self
    where
        I: IntoIterator<Item = CredentialEntry<'a>>,
    {
        let mut slots = self.slots.into_owned();
        slots.extend(entries.into_iter().map(CredentialSlot::from));
        self.slots = Cow::Owned(slots);
        self
    }
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for CredentialSet<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        if self.slots.is_empty() {
            return;
        }
        if let Some(v2) = ctx.host.as_v2() {
            v2.add_entry_set(self);
            for (i, slot) in self.slots.iter().enumerate() {
                for entry in slot.alternatives.iter() {
                    let set_ctx = CredmanSetContext {
                        v2,
                        set_id: &self.set_id,
                        set_index: i as i32,
                    };
                    CredmanApply::apply(entry, set_ctx);
                }
            }
            return;
        }

        // Host does not support sets (v1): only render when there is exactly one slot.
        let mut slots = self.slots.iter();
        let Some(slot) = slots.next() else {
            return;
        };
        if slots.next().is_some() {
            return;
        }
        for entry in slot.alternatives.iter() {
            CredmanApply::apply(entry, ctx);
        }
    }
}
