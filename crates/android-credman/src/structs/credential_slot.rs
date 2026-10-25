use crate::CredentialEntry;
use std::borrow::Cow;

/// A slot in a `CredentialSet` that contains one or more alternatives.
///
/// Credential Manager treats multiple entries for the same `set_index` as
/// alternatives that the user can pick between (OR-selection).
#[derive(Debug, Clone)]
pub struct CredentialSlot<'a> {
    pub alternatives: Cow<'a, [CredentialEntry<'a>]>,
}

impl<'a> CredentialSlot<'a> {
    /// Creates a new slot with one or more initial entries.
    pub fn new<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = CredentialEntry<'a>>,
    {
        Self {
            alternatives: Cow::Owned(entries.into_iter().collect()),
        }
    }

    /// Adds an alternative to this slot.
    pub fn add_alternative(mut self, entry: CredentialEntry<'a>) -> Self {
        let mut alternatives = self.alternatives.into_owned();
        alternatives.push(entry);
        self.alternatives = Cow::Owned(alternatives);
        self
    }
}

impl<'a> From<CredentialEntry<'a>> for CredentialSlot<'a> {
    fn from(entry: CredentialEntry<'a>) -> Self {
        CredentialSlot::new(core::iter::once(entry))
    }
}
