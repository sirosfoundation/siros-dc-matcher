//! The binary layout of a registration: the header, the section directory, the index entries,
//! and the spans that locate bytes inside a section. Every integer of the layout is an
//! unsigned 32-bit little-endian number.

use std::marker::PhantomData;

use siros_credential::Format;

use crate::error::{ByteCount, DirectoryFault, IndexFault, OutOfBounds, Within};

/// The bytes a registration starts with.
pub(crate) const MAGIC: [[u8; 4]; 2] = [*b"\x89SRG", *b"\r\n\x1a\n"];

/// The bytes of the header: the magic number and the version.
pub(crate) const HEADER_LENGTH: u64 = 12;

/// The bytes of the directory: one entry of 12 bytes per section, its kind, offset and length.
pub(crate) const DIRECTORY_LENGTH: u64 = 72;

/// Where the first section starts: after the header and the directory.
pub(crate) const SECTIONS_START: u32 = (HEADER_LENGTH + DIRECTORY_LENGTH) as u32;

/// The bytes of an index entry: the format, the span of the type's name in the names section,
/// and the span of its records in the records section.
pub(crate) const INDEX_ENTRY_LENGTH: u64 = 20;

/// [`INDEX_ENTRY_LENGTH`], for arithmetic on the index section's u32 offsets.
const INDEX_ENTRY_WORDS: u32 = 20;

/// The header as the blob holds it: the magic number's two words and the version.
pub(crate) type HeaderWords = [[u8; 4]; 3];

/// The directory as the blob holds it: per section, the words of its kind, offset and length.
pub(crate) type DirectoryWords = [[[u8; 4]; 3]; 6];

/// An index entry as the blob holds it: the words of its format, name span and records span.
pub(crate) type EntryWords = [[u8; 4]; 5];

/// A section of a registration, in the order the directory lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionKind {
    /// The facts every request reads: one CBOR map. Code 1.
    Facts,
    /// The index: one entry per credential type, sorted by format and type. Code 2.
    Index,
    /// The types' names. Code 3.
    Names,
    /// The credential records, those of a type together as one CBOR sequence. Code 4.
    Records,
    /// The projected transaction data definitions, each a JSON text. Code 5.
    Definitions,
    /// The icons' bytes. Code 6.
    Icons,
}

impl SectionKind {
    /// The sections, in the directory's order.
    pub(crate) const ALL: [Self; 6] = [
        Self::Facts,
        Self::Index,
        Self::Names,
        Self::Records,
        Self::Definitions,
        Self::Icons,
    ];

    /// The code the directory writes for the section.
    pub fn code(self) -> u32 {
        match self {
            Self::Facts => 1,
            Self::Index => 2,
            Self::Names => 3,
            Self::Records => 4,
            Self::Definitions => 5,
            Self::Icons => 6,
        }
    }
}

/// A section, as a type: what a [`Span`] lies in.
pub(crate) trait Part {
    /// The section.
    const KIND: SectionKind;
}

macro_rules! part {
    ($(#[$doc:meta])* $name:ident, $kind:ident) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub(crate) enum $name {}

        impl Part for $name {
            const KIND: SectionKind = SectionKind::$kind;
        }
    };
}

part!(
    /// The facts section.
    FactsPart,
    Facts
);
part!(
    /// The index section.
    IndexPart,
    Index
);
part!(
    /// The names section.
    NamesPart,
    Names
);
part!(
    /// The records section.
    RecordsPart,
    Records
);
part!(
    /// The definitions section.
    DefinitionsPart,
    Definitions
);
part!(
    /// The icons section.
    IconsPart,
    Icons
);

/// Bytes inside the section `S`: an offset from the section's start and a length that end
/// within it. [`Bounds::span`] makes one, after that check.
#[derive(Debug)]
pub(crate) struct Span<S> {
    offset: u32,
    length: u32,
    part: PhantomData<fn() -> S>,
}

// Derived impls would bound `S`, which is a type without values.
impl<S> Clone for Span<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for Span<S> {}

impl<S> PartialEq for Span<S> {
    fn eq(&self, other: &Self) -> bool {
        (self.offset, self.length) == (other.offset, other.length)
    }
}

impl<S> Eq for Span<S> {}

impl<S> std::hash::Hash for Span<S> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.offset, self.length).hash(state);
    }
}

impl<S> Span<S> {
    /// The bytes.
    pub(crate) fn length(self) -> u32 {
        self.length
    }
}

/// Where the section `S` lies in the blob, checked against the blob's length.
#[derive(Debug)]
pub(crate) struct Bounds<S> {
    start: u32,
    length: u32,
    part: PhantomData<fn() -> S>,
}

impl<S: Part> Bounds<S> {
    /// The span of `length` bytes at `offset` from the section's start.
    ///
    /// # Errors
    ///
    /// [`OutOfBounds`] for a span that ends past the section.
    pub(crate) fn span(&self, offset: u64, length: u64) -> Result<Span<S>, OutOfBounds> {
        let limit = u64::from(self.length);
        match offset.checked_add(length) {
            // The span ends within the section, whose length is a u32: so do both numbers.
            Some(end) if end <= limit => Ok(Span {
                offset: offset as u32,
                length: length as u32,
                part: PhantomData,
            }),
            _ => Err(OutOfBounds::new(
                Within::Section(S::KIND),
                offset,
                length,
                limit,
            )),
        }
    }

    /// The whole section.
    pub(crate) fn whole(&self) -> Span<S> {
        Span {
            offset: 0,
            length: self.length,
            part: PhantomData,
        }
    }

    /// The position of `span` in the blob.
    pub(crate) fn start_of(&self, span: Span<S>) -> u64 {
        wide::sum(self.start, span.offset)
    }

    fn at(located: Located) -> Self {
        Self {
            start: located.start,
            length: located.length,
            part: PhantomData,
        }
    }
}

/// Where a section the directory lists lies in the blob, before its kind types it.
#[derive(Debug, Clone, Copy, Default)]
struct Located {
    start: u32,
    length: u32,
}

/// The sections of a registration, as its directory lists them.
#[derive(Debug)]
pub(crate) struct Directory {
    pub(crate) facts: Bounds<FactsPart>,
    pub(crate) index: Bounds<IndexPart>,
    pub(crate) names: Bounds<NamesPart>,
    pub(crate) records: Bounds<RecordsPart>,
    pub(crate) definitions: Bounds<DefinitionsPart>,
    pub(crate) icons: Bounds<IconsPart>,
}

/// Why a directory is refused: its rule, or a section past the blob's end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectoryRefusal {
    /// The directory breaks a rule.
    Fault(DirectoryFault),
    /// A section ends past the blob.
    OutOfBlob(OutOfBounds),
}

impl Directory {
    /// The directory of `words`, for a blob of `blob` bytes: each section of
    /// [`SectionKind::ALL`] in order, the first right after the directory, each where the one
    /// before it ends, and the last at the blob's end.
    ///
    /// # Errors
    ///
    /// [`DirectoryRefusal`]: the first section that breaks the rule.
    pub(crate) fn parse(words: &DirectoryWords, blob: u64) -> Result<Self, DirectoryRefusal> {
        let mut end = u64::from(SECTIONS_START);
        let mut sections = [Located::default(); 6];
        for ((kind, entry), section) in SectionKind::ALL.iter().zip(words).zip(&mut sections) {
            let [code, offset, length] = entry.map(u32::from_le_bytes);
            if code != kind.code() {
                return Err(DirectoryRefusal::Fault(DirectoryFault::Kind {
                    expected: *kind,
                    found: code,
                }));
            }
            if u64::from(offset) != end {
                return Err(DirectoryRefusal::Fault(DirectoryFault::Offset {
                    kind: *kind,
                    offset,
                }));
            }
            end = wide::sum(offset, length);
            if end > blob {
                return Err(DirectoryRefusal::OutOfBlob(OutOfBounds::new(
                    Within::Blob,
                    offset.into(),
                    length.into(),
                    blob,
                )));
            }
            *section = Located {
                start: offset,
                length,
            };
        }
        if end != blob {
            return Err(DirectoryRefusal::Fault(DirectoryFault::Trailing {
                end: ByteCount::new(end),
            }));
        }
        let [facts, index, names, records, definitions, icons] = sections;
        Ok(Self {
            facts: Bounds::at(facts),
            index: Bounds::at(index),
            names: Bounds::at(names),
            records: Bounds::at(records),
            definitions: Bounds::at(definitions),
            icons: Bounds::at(icons),
        })
    }

    /// The number of index entries.
    ///
    /// # Errors
    ///
    /// The index section's length, back, when it is no multiple of an entry's.
    pub(crate) fn index_entries(&self) -> Result<u32, u32> {
        let length = self.index.length;
        match length % INDEX_ENTRY_WORDS {
            0 => Ok(length / INDEX_ENTRY_WORDS),
            _ => Err(length),
        }
    }

    /// The span of the index entry at `at`.
    ///
    /// # Errors
    ///
    /// [`OutOfBounds`] for a position at or past [`Directory::index_entries`].
    pub(crate) fn index_entry(&self, at: u32) -> Result<Span<IndexPart>, OutOfBounds> {
        self.index
            .span(wide::product(at, INDEX_ENTRY_WORDS), INDEX_ENTRY_LENGTH)
    }
}

/// An index entry: the format of a type, its name, and the span of its records.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RawEntry {
    pub(crate) format: Format,
    pub(crate) name: Span<NamesPart>,
    pub(crate) records: Span<RecordsPart>,
}

impl RawEntry {
    /// The entry of `words`, its spans in the sections of `directory`.
    ///
    /// # Errors
    ///
    /// [`IndexFault`]: an unknown format code, or a span past its section.
    pub(crate) fn parse(words: &EntryWords, directory: &Directory) -> Result<Self, IndexFault> {
        let [format, name_offset, name_length, records_offset, records_length] =
            words.map(u32::from_le_bytes);
        let format = format_of(format).ok_or(IndexFault::Format(format))?;
        let name = directory
            .names
            .span(name_offset.into(), name_length.into())
            .map_err(IndexFault::Span)?;
        let records = directory
            .records
            .span(records_offset.into(), records_length.into())
            .map_err(IndexFault::Span)?;
        Ok(Self {
            format,
            name,
            records,
        })
    }
}

/// The code an index entry writes for `format`: 1 for `dc+sd-jwt`, 2 for `mso_mdoc`. The index
/// sorts by it.
pub(crate) fn format_code(format: Format) -> u32 {
    match format {
        Format::SdJwtVc => 1,
        Format::Mdoc => 2,
    }
}

/// The format of the code `code`.
fn format_of(code: u32) -> Option<Format> {
    [Format::SdJwtVc, Format::Mdoc]
        .into_iter()
        .find(|format| format_code(*format) == code)
}

/// Arithmetic on u32 values widened to u64: no sum or product of two of them overflows a u64.
mod wide {
    #![expect(
        clippy::arithmetic_side_effects,
        reason = "two u32 values widened to u64 neither sum nor multiply past u64::MAX"
    )]

    /// `a + b`.
    pub(crate) fn sum(a: u32, b: u32) -> u64 {
        u64::from(a) + u64::from(b)
    }

    /// `a × b`.
    pub(crate) fn product(a: u32, b: u32) -> u64 {
        u64::from(a) * u64::from(b)
    }
}
