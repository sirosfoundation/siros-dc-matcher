use crate::entry::DelegationType;
use crate::levels::{EntryKey, V2, V5, V6, V7};
use crate::set::{EntryKind, EntrySet, SetEntry, SetSink};

/// The host's entry sets, from [`Host::entry_sets`](crate::Host::entry_sets):
/// the level-2 host and the host's default delegation.
#[derive(Clone, Copy)]
pub struct EntrySets<'h> {
    host: &'h dyn V2,
    delegation: Option<DelegationType>,
}

impl<'h> EntrySets<'h> {
    pub(crate) fn new(host: &'h dyn V2, delegation: Option<DelegationType>) -> Self {
        Self { host, delegation }
    }

    fn emit<K: EntryKind>(&self, entry: &SetEntry<'_, K>, key: &EntryKey<'_>) {
        let metadata = entry.metadata(self.host.level());
        entry.kind().add(self.host, key, &metadata);
        if let (Some(delegation), Some(host)) = (
            entry.delegation().or(self.delegation),
            self.host.version::<dyn V7>(),
        ) {
            host.set_delegation_type_for_entry_in_set(key, delegation);
        }
        if let (Some(link), Some(host)) = (entry.link(), self.host.version::<dyn V6>()) {
            host.set_additional_disclaimer_and_url_for_verification_entry_in_credential_set(
                key, &link,
            );
        }
        for field in entry.fields() {
            self.host.add_field_to_entry_set(key, field);
        }
        if let (Some(text), Some(host)) =
            (entry.metadata_display_text(), self.host.version::<dyn V5>())
        {
            host.add_metadata_display_text_to_entry_set(key, text);
        }
    }
}

impl SetSink for EntrySets<'_> {
    fn add_entry_set<K: EntryKind>(&mut self, set: &EntrySet<'_, K>) {
        // A slot occupies more than 4 bytes and wasm32 addresses 4 GiB, so
        // no set holds more slots than an i32 counts: the cast and the
        // position counter below are exact.
        self.host.add_entry_set(set.id(), set.slot_count() as i32);
        for (set_index, slot) in (0_i32..).zip(set.slots()) {
            for entry in slot.alternatives() {
                let key = EntryKey {
                    set_id: set.id(),
                    set_index,
                    cred_id: entry.cred_id(),
                };
                self.emit(entry, &key);
            }
        }
    }
}
