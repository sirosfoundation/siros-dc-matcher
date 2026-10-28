//! The index of a registration, read whole when it opens, as LevelDB reads a table's index
//! block: the entries sort strictly, and the names and the records of the types tile their
//! sections in the index's order. A search then runs in memory.

use std::cmp::Ordering;

use crate::error::{ByteCount, IndexFault, RegistrationError, TileFault};
use crate::ids::KeyIndex;
use crate::layout::{format_of, Directory, EntryWords, NamesPart, RecordsPart, Span, Tiles};
use crate::registration::{RegisteredType, TypeName, TypeNameEmpty};

/// The index entries, sorted strictly by type.
#[derive(Debug)]
pub(crate) struct Index {
    entries: Vec<IndexEntry>,
}

/// An index entry: a type and the span of its records.
#[derive(Debug)]
pub(crate) struct IndexEntry {
    pub(crate) key: RegisteredType,
    pub(crate) records: Span<RecordsPart>,
}

impl Index {
    /// The index of `words`, the entries of the index section, and `names`, the bytes of the
    /// names section, in the sections of `directory`.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::Index`]: the first entry that breaks a rule;
    /// [`RegistrationError::Uncovered`]: names or records whose tiles end before their
    /// section's end; [`RegistrationError::TooLong`]: more entries than a buffer holds.
    pub(crate) fn parse(
        words: &[EntryWords],
        names: &[u8],
        directory: &Directory,
    ) -> Result<Self, RegistrationError> {
        let too_long = || {
            let length = u64::from(directory.index.length());
            RegistrationError::TooLong(ByteCount::new(length))
        };
        // A buffer holds at most isize::MAX bytes.
        if words
            .len()
            .checked_mul(size_of::<IndexEntry>())
            .is_none_or(|bytes| isize::try_from(bytes).is_err())
        {
            return Err(too_long());
        }
        let mut entries: Vec<IndexEntry> = Vec::with_capacity(words.len());
        let mut tiles = EntryTiles {
            names: Tiles::of(&directory.names),
            records: Tiles::of(&directory.records),
        };
        for (at, words) in words.iter().enumerate() {
            let entry = tiles
                .entry(words, names, entries.last())
                .map_err(|fault| RegistrationError::Index(KeyIndex::new(at), fault))?;
            entries.push(entry);
        }
        tiles.finish()?;
        Ok(Self { entries })
    }

    /// The span of the records of `key`, when the index lists it: a binary search.
    pub(crate) fn find(&self, key: &RegisteredType) -> Option<Span<RecordsPart>> {
        let at = self
            .entries
            .binary_search_by(|entry| entry.key.cmp(key))
            .ok()?;
        self.entries.get(at).map(|entry| entry.records)
    }

    /// The entries, in order.
    pub(crate) fn entries(&self) -> &[IndexEntry] {
        &self.entries
    }
}

/// The tiles the names and the records of the entries read so far take.
struct EntryTiles {
    names: Tiles<NamesPart>,
    records: Tiles<RecordsPart>,
}

impl EntryTiles {
    /// The entry of `words`, its name in `names`, after `before`, the entry before it.
    fn entry(
        &mut self,
        words: &EntryWords,
        names: &[u8],
        before: Option<&IndexEntry>,
    ) -> Result<IndexEntry, IndexFault> {
        let [format, name_offset, name_length, records_offset, records_length] =
            words.map(u32::from_le_bytes);
        let format = format_of(format).ok_or(IndexFault::Format(format))?;
        let name = self
            .names
            .next_of(name_offset, name_length, names)
            .map_err(IndexFault::Name)?;
        let name = std::str::from_utf8(name).map_err(IndexFault::NameText)?;
        // A tile holds a byte at least.
        let name =
            TypeName::new(name).map_err(|TypeNameEmpty| IndexFault::Name(TileFault::Empty))?;
        let key = RegisteredType::new(format, name);
        match before.map(|before| before.key.cmp(&key)) {
            Some(Ordering::Equal) => return Err(IndexFault::Repeated),
            Some(Ordering::Greater) => return Err(IndexFault::Order),
            Some(Ordering::Less) | None => {}
        }
        let records = self
            .records
            .next(records_offset, records_length)
            .map_err(IndexFault::Records)?;
        Ok(IndexEntry { key, records })
    }

    /// Checks that the names and the records end at their sections' ends.
    fn finish(self) -> Result<(), RegistrationError> {
        self.names.finish()?;
        self.records.finish()
    }
}
