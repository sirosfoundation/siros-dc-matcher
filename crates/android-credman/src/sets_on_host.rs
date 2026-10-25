use crate::entry::DelegationType;
use crate::levels::imp::Credman;
use crate::levels::{EntryKey, V2};
use crate::set::{EntryKind, EntrySet, Sent, SetSink};

/// The host's entry sets, from [`Host::entry_sets`](crate::Host::entry_sets):
/// the level-2 host and the host's default delegation.
#[derive(Clone, Copy)]
pub struct EntrySets<'h> {
    host: &'h Credman,
    delegation: Option<Sent<DelegationType>>,
}

impl<'h> EntrySets<'h> {
    pub(crate) fn new(host: &'h Credman, delegation: Option<Sent<DelegationType>>) -> Self {
        Self { host, delegation }
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
                entry.send(self.host, &key, self.delegation);
            }
        }
    }
}
