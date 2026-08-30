//! Where matched credentials go.
//!
//! Abstracted so the engine can be driven by the real Credential Manager host
//! in production and by an in-memory recorder in tests, without the matching
//! logic knowing the difference.

/// Receives the entries a match produced.
///
/// Entries are grouped into *sets* because DCQL `credential_sets` can be
/// satisfied by a combination of several credentials, which the picker has to
/// present and select as one unit.
pub trait PickerSink {
    /// Begin a set of `len` entries that are selected together.
    fn begin_set(&mut self, set_id: &str, len: usize);

    /// Add an entry to the current set.
    ///
    /// `metadata` is opaque to the platform and survives the picker
    /// round-trip, so it carries the decision this matcher already made —
    /// which DCQL query matched, which capability was selected — rather than
    /// leaving the wallet to re-derive it after selection.
    fn add_entry(&mut self, set_id: &str, index: usize, entry: &Entry<'_>);

    /// Add a displayable field to an entry already added to the set.
    ///
    /// `credential_id` must be the id the entry was added with: the platform
    /// keys fields by credential id as well as by set position, so a mismatch
    /// leaves the field silently unattached.
    fn add_field(
        &mut self,
        set_id: &str,
        index: usize,
        credential_id: &str,
        name: &str,
        value: &str,
    );
}

/// One credential offered in the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Wallet-side credential identifier, returned on selection.
    pub credential_id: &'a str,
    /// Primary line shown to the user.
    pub title: &'a str,
    /// Secondary line, typically the issuer.
    pub subtitle: &'a str,
    /// Opaque payload handed back to the wallet on selection.
    pub metadata: &'a str,
    /// Icon bytes, borrowed from the registered blob.
    ///
    /// `None` when the credential has no icon, or when its reference did not
    /// fall inside the blob's icon buffer — a credential should lose its
    /// picture over that, not its entry.
    pub icon: Option<&'a [u8]>,
}
