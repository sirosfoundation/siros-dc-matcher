//! The table that opens the icons and the definitions sections: the count of its entries, then
//! the offset and the length of each, which tile the rest of the section in the table's order.
//! A record names an icon or a definition by its number in the table: a whole entry.

use crate::error::{RegistrationError, TableFault, Unlisted};
use crate::ids::TableIndex;
use crate::layout::{wide, Bounds, DefinitionsPart, IconsPart, Part, Span, Tiles};

/// The count of a table's entries, as the blob holds it.
pub(crate) type CountWords = [[u8; 4]; 1];

/// A table entry as the blob holds it: the words of its offset and its length.
pub(crate) type TableEntryWords = [[u8; 4]; 2];

/// The bytes of the count.
const COUNT_LENGTH: u32 = 4;

/// The bytes of a table entry.
const ENTRY_LENGTH: u32 = 8;

/// The entries of the table of the section `S`, in order.
#[derive(Debug)]
pub(crate) struct Table<S> {
    entries: Vec<Span<S>>,
}

/// The tables a record names its icon and its definitions in.
#[derive(Debug)]
pub(crate) struct Tables {
    pub(crate) icons: Table<IconsPart>,
    pub(crate) definitions: Table<DefinitionsPart>,
}

impl<S: Part> Table<S> {
    /// The span of the count, at the start of the section `bounds`.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::Table`] for a section of fewer bytes.
    pub(crate) fn count(bounds: &Bounds<S>) -> Result<Span<S>, RegistrationError> {
        bounds
            .span(0, COUNT_LENGTH.into())
            .map_err(|error| refused::<S>(TableFault::Past(error)))
    }

    /// The span of the words of `count` entries, after the count in the section `bounds`.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::Table`] for entries that end past the section.
    pub(crate) fn words(count: u32, bounds: &Bounds<S>) -> Result<Span<S>, RegistrationError> {
        bounds
            .span(COUNT_LENGTH.into(), wide::product(count, ENTRY_LENGTH))
            .map_err(|error| refused::<S>(TableFault::Past(error)))
    }

    /// The table of `words`, the entries at `table` in the section `bounds`.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::Table`] for the first entry that is no tile of the section after the
    /// table; [`RegistrationError::Uncovered`] for entries that end before the section's end.
    pub(crate) fn parse(
        words: &[TableEntryWords],
        table: Span<S>,
        bounds: &Bounds<S>,
    ) -> Result<Self, RegistrationError> {
        let mut tiles = Tiles::after(bounds, table);
        let mut entries = Vec::with_capacity(words.len());
        for (at, [offset, length]) in words.iter().enumerate() {
            let span = tiles
                .next(u32::from_le_bytes(*offset), u32::from_le_bytes(*length))
                .map_err(|fault| refused::<S>(TableFault::Entry(TableIndex::new(at), fault)))?;
            entries.push(span);
        }
        tiles.finish()?;
        Ok(Self { entries })
    }

    /// The entry numbered `index`, and its number.
    ///
    /// # Errors
    ///
    /// [`Unlisted`] for a number at or past the count.
    pub(crate) fn entry(&self, index: u64) -> Result<(TableIndex, Span<S>), Unlisted> {
        usize::try_from(index)
            .ok()
            .and_then(|at| Some((TableIndex::new(at), *self.entries.get(at)?)))
            .ok_or(Unlisted {
                index,
                // The count is a u32 word.
                entries: self.entries.len() as u32,
            })
    }
}

/// The refusal of the table of the section `S`.
fn refused<S: Part>(fault: TableFault) -> RegistrationError {
    RegistrationError::Table(S::KIND, fault)
}
