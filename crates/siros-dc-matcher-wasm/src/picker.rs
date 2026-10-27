//! Picker entries, from the matcher's decisions to the host's types.
//!
//! The matcher describes each entry in Rust strings ([`Member`]); this module
//! turns a combination of them into an [`EntrySet`] of NUL-terminated UTF-8
//! strings and hands it to a [`SetSink`]: the host on a device, a stand-in in
//! a test.

use android_credman::{
    C8String, C8StringExt, EntrySet, Field, SetEntry, SetSink, Slot, VerificationDisplay,
};

/// The entries this matcher emits: verification entries alone, so it links
/// `AddEntryToSet` and none of the payment functions.
type Entry<'a> = SetEntry<'a, VerificationDisplay<'a>>;

/// One credential offered in the picker, with the fields shown on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member<'a> {
    /// Wallet-side credential identifier, returned on selection. Fields
    /// attach to the entry through it.
    pub credential_id: &'a str,
    /// Primary line shown to the user.
    pub title: &'a str,
    /// Secondary line, typically the issuer.
    pub subtitle: &'a str,
    /// JSON handed back to the wallet on selection, as `data` in the
    /// standard metadata object.
    pub data: String,
    /// Image bytes. The host drops an entry without them.
    pub icon: &'a [u8],
    /// Why the verifier is asking, shown with the entry: the credential sets' `purpose`.
    ///
    /// `None` and `Some("")` differ to the host: it renders the *presence*
    /// of this field, so an empty string produces a label with nothing in
    /// it. Build it with [`siros_display::purpose::line`], which
    /// returns `None` for a reason that is blank as well as for one that is
    /// absent.
    pub disclaimer: Option<&'a str>,
    /// Display fields as `(name, value)`, in order.
    pub fields: Vec<(String, String)>,
}

/// A member's strings in host form, owned while the set is emitted.
struct HostStrings {
    credential_id: C8String,
    title: C8String,
    subtitle: C8String,
    data: C8String,
    disclaimer: Option<C8String>,
    fields: Vec<(C8String, C8String)>,
}

impl HostStrings {
    fn of(member: &Member<'_>) -> Self {
        Self {
            credential_id: c(member.credential_id),
            title: c(member.title),
            subtitle: c(member.subtitle),
            data: c(&member.data),
            disclaimer: member.disclaimer.map(c),
            fields: member
                .fields
                .iter()
                .map(|(name, value)| (c(name), c(value)))
                .collect(),
        }
    }

    fn fields(&self) -> Vec<Field<'_>> {
        self.fields
            .iter()
            .map(|(name, value)| Field {
                name,
                value: Some(value),
            })
            .collect()
    }

    /// The entry, with the subtitle always present and no warning: nothing
    /// the matcher knows is a warning, and a verifier's purpose least of all.
    fn entry<'a>(&'a self, icon: &'a [u8], fields: &'a [Field<'a>]) -> Entry<'a> {
        let display = VerificationDisplay {
            icon,
            title: &self.title,
            subtitle: Some(&self.subtitle),
            disclaimer: self.disclaimer.as_deref(),
            warning: None,
        };
        SetEntry::new(&self.credential_id, display)
            .with_data(&self.data)
            .with_fields(fields)
    }
}

/// Emits `members` as one set, each member in its own slot, in order.
///
/// A combination with no members gives the user nothing to select, so it
/// emits nothing.
pub fn emit_set(sink: &mut impl SetSink, set_id: &str, members: &[Member<'_>]) {
    let strings: Vec<HostStrings> = members.iter().map(HostStrings::of).collect();
    let fields: Vec<Vec<Field<'_>>> = strings.iter().map(HostStrings::fields).collect();
    let entries: Vec<Entry<'_>> = members
        .iter()
        .zip(&strings)
        .zip(&fields)
        .map(|((member, strings), fields)| strings.entry(member.icon, fields))
        .collect();
    let slots: Vec<Slot<'_, VerificationDisplay<'_>>> = entries.iter().map(Slot::one).collect();
    let Some((first, others)) = slots.split_first() else {
        return;
    };
    let id = c(set_id);
    sink.add_entry_set(&EntrySet::new(&id, *first, others));
}

/// `text` as a host string, each NUL replaced by a space.
///
/// A credential whose title contains a NUL is pathological, but dropping the
/// whole picker entry over it would present as "no matching credential" with
/// no way to tell why.
fn c(text: &str) -> C8String {
    C8String::from_str_lossy(text)
}
