//! The reader of a registration: the header, the directory, the index, the names, the tables
//! of the definitions and the icons, and the facts when it opens, then each part a caller asks
//! for, read through `Read + Seek` when asked.

use std::io::{Read, Seek, SeekFrom};
use std::marker::PhantomData;

use siros_codec::{cbor, json};
use siros_transaction_data::Projected;

use crate::error::{
    ByteCount, DefinitionFault, FactsFault, OutOfBounds, RegistrationError, Within,
};
use crate::ids::{CredentialIndex, RecordIndex};
use crate::index::Index;
use crate::layout::{
    Bounds, Directory, DirectoryRefusal, DirectoryWords, EntryWords, HeaderWords, Part,
    RecordsPart, Span, HEADER_LENGTH, MAGIC,
};
use crate::record::{self, Positioned};
use crate::registration::{
    Brand, DefinitionRef, Facts, Icon, IconRef, Projection, RegisteredCredential, RegisteredType,
    Version,
};
use crate::table::{CountWords, Table, TableEntryWords, Tables};

/// A registration the wallet wrote, open for reading, of the brand `'id`: the icons and the
/// definitions it gives name parts of this registration alone. Opening reads its header, its
/// directory, its index, its names, the tables of its definitions and its icons, and its facts;
/// each other part is read when a caller asks for it, and a definition or an icon once.
#[derive(Debug)]
pub struct Registration<'id, R> {
    blob: Blob<R>,
    version: Version,
    directory: Directory,
    index: Index,
    tables: Tables,
    facts: Facts<IconRef<'id>>,
    definitions: Vec<Cached<DefinitionRef<'id>, Projected>>,
    icons: Vec<Cached<IconRef<'id>, Icon>>,
    brand: Brand<'id>,
}

/// A part read, and where it lies.
#[derive(Debug)]
struct Cached<K, V> {
    at: K,
    part: V,
}

/// The source of a registration and its length.
#[derive(Debug)]
struct Blob<R> {
    source: R,
    length: u64,
}

impl<R: Read + Seek> Registration<'_, R> {
    /// What `read` gives of the registration of `source`: [`Version::CURRENT`] of the layout of
    /// `docs/registration.md`. Reads the header, the directory, the index, the names, the
    /// tables of the definitions and the icons, and the facts, then hands the registration to
    /// `read` under a brand of its own.
    ///
    /// An icon or a definition names a part of the registration that gave it, and the compiler
    /// refuses it on another. This reads the wallet's icon of `first` from `first`:
    ///
    /// ```
    /// # use std::io::Cursor;
    /// # use siros_registration::Registration;
    /// fn icons(first: &[u8], second: &[u8]) -> bool {
    ///     let read = Registration::open(Cursor::new(first), |mut first| {
    ///         let opened = Registration::open(Cursor::new(second), |mut second| {
    ///             let icon = *first.facts().default_icon();
    ///             first.icon(icon).is_ok() && second.icon(*second.facts().default_icon()).is_ok()
    ///         });
    ///         opened.unwrap_or(false)
    ///     });
    ///     read.unwrap_or(false)
    /// }
    /// ```
    ///
    /// and this, which reads it from `second`, does not build (E0521: the brands differ):
    ///
    /// ```compile_fail,E0521
    /// # use std::io::Cursor;
    /// # use siros_registration::Registration;
    /// fn icons(first: &[u8], second: &[u8]) -> bool {
    ///     let read = Registration::open(Cursor::new(first), |mut first| {
    ///         let opened = Registration::open(Cursor::new(second), |mut second| {
    ///             let icon = *first.facts().default_icon();
    ///             second.icon(icon).is_ok() && second.icon(*second.facts().default_icon()).is_ok()
    ///         });
    ///         opened.unwrap_or(false)
    ///     });
    ///     read.unwrap_or(false)
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: the first rule the parts it reads break, the magic number first.
    pub fn open<T>(
        source: R,
        read: impl for<'id> FnOnce(Registration<'id, R>) -> T,
    ) -> Result<T, RegistrationError> {
        Ok(read(Registration::read(source)?))
    }
}

impl<'id, R: Read + Seek> Registration<'id, R> {
    /// The registration of `source`, of the brand `'id`, which [`Registration::open`] chooses.
    fn read(source: R) -> Result<Self, RegistrationError> {
        let mut blob = Blob::of(source)?;
        let header: HeaderWords = blob.words(0)?;
        let [first, second, version] = header;
        if [first, second] != MAGIC {
            return Err(RegistrationError::Magic);
        }
        let version =
            Version::of(u32::from_le_bytes(version)).map_err(RegistrationError::Version)?;
        let words: DirectoryWords = blob.words(HEADER_LENGTH)?;
        let directory = Directory::parse(&words, blob.length).map_err(|refusal| match refusal {
            DirectoryRefusal::Fault(fault) => RegistrationError::Directory(fault),
            DirectoryRefusal::OutOfBlob(error) => RegistrationError::OutOfBlob(error),
        })?;
        let index = blob.index(&directory)?;
        let tables = Tables {
            definitions: blob.table(&directory.definitions)?,
            icons: blob.table(&directory.icons)?,
        };
        let bytes =
            blob.read_at_most(&directory.facts, directory.facts.whole(), cbor::MAX_INPUT)?;
        let item = cbor::decode(&bytes)
            .map_err(|error| RegistrationError::Facts(FactsFault::Cbor(error)))?;
        let facts = record::facts(&item, &tables.icons).map_err(RegistrationError::Facts)?;
        Ok(Self {
            blob,
            version,
            directory,
            index,
            tables,
            facts,
            definitions: Vec::new(),
            icons: Vec::new(),
            brand: PhantomData,
        })
    }

    /// The format version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The facts every request reads.
    pub fn facts(&self) -> &Facts<IconRef<'id>> {
        &self.facts
    }

    /// The credentials of the types of `types`, in the wallet's order. Reads the records of each
    /// type the index lists, once.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: a record that breaks a rule, records of a type out of the wallet's
    /// order, or two credentials with one position, `credentialId` or batch.
    pub fn credentials(
        &mut self,
        types: &[RegisteredType],
    ) -> Result<Vec<RegisteredCredential<DefinitionRef<'id>, IconRef<'id>>>, RegistrationError>
    {
        let mut runs = Vec::new();
        for (at, key) in types.iter().enumerate() {
            if types.iter().take(at).any(|earlier| earlier == key) {
                continue;
            }
            if let Some(records) = self.index.find(key) {
                runs.push(self.records_of(key, records)?);
            }
        }
        in_wallet_order(runs)
    }

    /// The definition `at` names, projected to the wallet's language: an entry of the
    /// definitions table, which a credential of this registration gave.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::Definition`]: no UTF-8, no projection, or another language;
    /// [`RegistrationError::TooLong`]: a definition longer than the JSON reader reads; or an
    /// entry past the blob.
    pub fn definition(&mut self, at: DefinitionRef<'id>) -> Result<Projected, RegistrationError> {
        if let Some(read) = self.definitions.iter().find(|read| read.at == at) {
            return Ok(read.part.clone());
        }
        let bytes =
            self.blob
                .read_at_most(&self.directory.definitions, at.span(), json::MAX_TEXT)?;
        let refused = |fault| RegistrationError::Definition(at.number(), fault);
        let text = std::str::from_utf8(&bytes).map_err(|e| refused(DefinitionFault::Utf8(e)))?;
        let definition =
            Projected::parse(text).map_err(|e| refused(DefinitionFault::Projection(e)))?;
        if definition.language() != self.facts.language() {
            return Err(refused(DefinitionFault::Language));
        }
        self.definitions.push(Cached {
            at,
            part: definition.clone(),
        });
        Ok(definition)
    }

    /// The icon `at` names: an entry of the icons table, which the facts or a credential of this
    /// registration gave.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: an entry past the blob, an icon longer than a buffer holds, or a
    /// source that fails.
    pub fn icon(&mut self, at: IconRef<'id>) -> Result<Icon, RegistrationError> {
        if let Some(read) = self.icons.iter().find(|read| read.at == at) {
            return Ok(read.part.clone());
        }
        let icon = Icon::of_held(self.blob.read(&self.directory.icons, at.span())?);
        self.icons.push(Cached {
            at,
            part: icon.clone(),
        });
        Ok(icon)
    }

    /// The credentials the records of `key` at `span` hold.
    fn records_of(
        &mut self,
        key: &RegisteredType,
        span: Span<RecordsPart>,
    ) -> Result<Vec<Positioned<'id>>, RegistrationError> {
        records_of(&mut self.blob, &self.directory, &self.tables, key, span)
    }

    /// The whole registration: the records of every type of the index, in its order, and every
    /// definition and icon they name.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: the first part that breaks a rule.
    pub fn projection(&mut self) -> Result<Projection, RegistrationError> {
        let Self {
            blob,
            directory,
            index,
            tables,
            ..
        } = self;
        let runs = index
            .entries()
            .iter()
            .map(|entry| records_of(blob, directory, tables, &entry.key, entry.records))
            .collect::<Result<Vec<_>, _>>()?;
        let credentials = in_wallet_order(runs)?
            .into_iter()
            .map(|credential| {
                credential
                    .try_map_definitions(|at| self.definition(at))?
                    .try_map_icon(|at| self.icon(at))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let facts = self.facts.clone().try_map_icon(|at| self.icon(at))?;
        Ok(Projection { facts, credentials })
    }
}

/// The credentials the records of `key` at `span` in `blob` hold, in the sections of
/// `directory`, their icons and definitions numbered in `tables`: a CBOR sequence of records,
/// in the wallet's order.
fn records_of<'id, R: Read + Seek>(
    blob: &mut Blob<R>,
    directory: &Directory,
    tables: &Tables,
    key: &RegisteredType,
    span: Span<RecordsPart>,
) -> Result<Vec<Positioned<'id>>, RegistrationError> {
    let bytes = blob.read_at_most(&directory.records, span, cbor::MAX_INPUT)?;
    let items = cbor::decode_sequence(&bytes)
        .map_err(|error| RegistrationError::Records(key.clone(), error))?;
    let mut records: Vec<Positioned<'id>> = Vec::new();
    for (at, item) in items.iter().enumerate() {
        let record = RecordIndex::new(at);
        let read = record::credential(item, key, tables).map_err(|fault| {
            RegistrationError::Credential {
                credential_type: key.clone(),
                record,
                fault,
            }
        })?;
        if records
            .last()
            .is_some_and(|ahead| ahead.position >= read.position)
        {
            return Err(RegistrationError::RecordOrder {
                credential_type: key.clone(),
                record,
            });
        }
        records.push(read);
    }
    Ok(records)
}

impl<R: Read + Seek> Blob<R> {
    /// The blob of `source`, its length the end `source` seeks to.
    fn of(mut source: R) -> Result<Self, RegistrationError> {
        let length = source.seek(SeekFrom::End(0))?;
        Ok(Self { source, length })
    }

    /// The index of the blob of `directory`: the index and the names sections, read whole.
    fn index(&mut self, directory: &Directory) -> Result<Index, RegistrationError> {
        let entries = directory
            .index_entries()
            .map_err(|length| RegistrationError::IndexLength(ByteCount::new(length.into())))?;
        let index = &directory.index;
        // The entries take the section's bytes: a buffer holds them when it holds the section.
        // A u32 fits the usize of every target the crate builds for.
        self.buffer(index.length()).map(drop)?;
        let mut words = vec![EntryWords::default(); entries as usize];
        self.fill(
            index.start_of(index.whole()),
            words.as_flattened_mut().as_flattened_mut(),
        )?;
        let names = self.read(&directory.names, directory.names.whole())?;
        Index::parse(&words, &names, directory)
    }

    /// The table of the section `bounds` locates, read whole.
    fn table<S: Part>(&mut self, bounds: &Bounds<S>) -> Result<Table<S>, RegistrationError> {
        let [count]: CountWords = self.words(bounds.start_of(Table::count(bounds)?))?;
        let count = u32::from_le_bytes(count);
        let table = Table::words(count, bounds)?;
        // The words take the table's bytes: a buffer holds them when it holds the table. A u32
        // fits the usize of every target the crate builds for.
        self.buffer(table.length()).map(drop)?;
        let mut words = vec![TableEntryWords::default(); count as usize];
        self.fill(
            bounds.start_of(table),
            words.as_flattened_mut().as_flattened_mut(),
        )?;
        Table::parse(&words, table, bounds)
    }

    /// The words of `W` at `at` from the blob's start.
    fn words<W: Words>(&mut self, at: u64) -> Result<W, RegistrationError> {
        let mut words = W::default();
        self.fill(at, words.bytes())?;
        Ok(words)
    }

    /// The bytes `span` spans in `bounds`.
    fn read<S: Part>(
        &mut self,
        bounds: &Bounds<S>,
        span: Span<S>,
    ) -> Result<Vec<u8>, RegistrationError> {
        let mut bytes = vec![0; self.buffer(span.length())?];
        self.fill(bounds.start_of(span), &mut bytes)?;
        Ok(bytes)
    }

    /// The size of a buffer of `length` bytes. Below `isize::MAX`, the most a buffer holds,
    /// `vec!` aborts when the platform has no memory for it, and allocates it otherwise.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::TooLong`] for a length past `isize::MAX`.
    fn buffer(&self, length: u32) -> Result<usize, RegistrationError> {
        isize::try_from(length)
            .ok()
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(RegistrationError::TooLong(ByteCount::new(length.into())))
    }

    /// The bytes `span` spans in `bounds`, a part a reader decodes that holds at most `most`
    /// bytes.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::TooLong`] for a part longer than `most`: the bytes stay unread.
    fn read_at_most<S: Part>(
        &mut self,
        bounds: &Bounds<S>,
        span: Span<S>,
        most: usize,
    ) -> Result<Vec<u8>, RegistrationError> {
        let length = span.length();
        if usize::try_from(length).map_or(true, |length| length > most) {
            return Err(RegistrationError::TooLong(ByteCount::new(length.into())));
        }
        self.read(bounds, span)
    }

    /// Fills `out` with the bytes at `at` from the blob's start.
    fn fill(&mut self, at: u64, out: &mut [u8]) -> Result<(), RegistrationError> {
        // A slice's length is at most isize::MAX, which a u64 holds.
        self.within(at, out.len() as u64)?;
        // `seek` gives the position it was asked for.
        self.source
            .seek(SeekFrom::Start(at))
            .and_then(|_| self.source.read_exact(out))?;
        Ok(())
    }

    /// Checks that the `length` bytes at `at` lie within the blob: the header and the directory
    /// of a shorter blob lie past it.
    fn within(&self, at: u64, length: u64) -> Result<(), RegistrationError> {
        match at.checked_add(length) {
            Some(end) if end <= self.length => Ok(()),
            _ => Err(RegistrationError::OutOfBlob(OutOfBounds::new(
                Within::Blob,
                at,
                length,
                self.length,
            ))),
        }
    }
}

/// Fixed-size words the layout reads whole.
trait Words: Default {
    /// The words' bytes.
    fn bytes(&mut self) -> &mut [u8];
}

impl<const N: usize> Words for [[u8; 4]; N]
where
    [[u8; 4]; N]: Default,
{
    fn bytes(&mut self) -> &mut [u8] {
        self.as_flattened_mut()
    }
}

impl Words for DirectoryWords {
    fn bytes(&mut self) -> &mut [u8] {
        self.as_flattened_mut().as_flattened_mut()
    }
}

/// The credentials of `runs`, each the records of one type in the wallet's order, merged into
/// that order.
///
/// # Errors
///
/// [`RegistrationError::PositionRepeated`] and [`RegistrationError::EntryRepeated`].
fn in_wallet_order<'id>(
    runs: Vec<Vec<Positioned<'id>>>,
) -> Result<Vec<RegisteredCredential<DefinitionRef<'id>, IconRef<'id>>>, RegistrationError> {
    let mut ordered: Vec<RegisteredCredential<DefinitionRef<'id>, IconRef<'id>>> = Vec::new();
    let mut previous: Option<CredentialIndex> = None;
    for record in runs.into_iter().fold(Vec::new(), merge) {
        if previous == Some(record.position) {
            return Err(RegistrationError::PositionRepeated(record.position));
        }
        let entry = record.credential.entry();
        if ordered.iter().any(|other| {
            let other = other.entry();
            other.credential_id() == entry.credential_id() || other.batch_id() == entry.batch_id()
        }) {
            return Err(RegistrationError::EntryRepeated(record.position));
        }
        previous = Some(record.position);
        ordered.push(record.credential);
    }
    Ok(ordered)
}

/// `first` and `second`, each in the wallet's order, as one run in that order.
fn merge<'id>(first: Vec<Positioned<'id>>, second: Vec<Positioned<'id>>) -> Vec<Positioned<'id>> {
    let mut first = first.into_iter().peekable();
    let mut second = second.into_iter().peekable();
    let mut merged = Vec::new();
    loop {
        let next = match second.peek().map(|record| record.position) {
            Some(position) => first
                .next_if(|record| record.position <= position)
                .or_else(|| second.next()),
            None => first.next(),
        };
        let Some(record) = next else {
            return merged;
        };
        merged.push(record);
    }
}
