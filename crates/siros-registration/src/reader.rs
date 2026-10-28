//! The reader of a registration: the header, the directory and the facts when it opens, then
//! each part a caller asks for, read through `Read + Seek` when asked.

use std::cmp::Ordering;
use std::io::{Read, Seek, SeekFrom};

use siros_codec::cbor;
use siros_transaction_data::Projected;

use crate::error::{
    ByteCount, DefinitionFault, FactsFault, IndexFault, OutOfBounds, RegistrationError, Within,
};
use crate::ids::{CredentialIndex, KeyIndex, RecordIndex};
use crate::layout::{
    Bounds, Directory, DirectoryRefusal, DirectoryWords, EntryWords, HeaderWords, Part, RawEntry,
    RecordsPart, Span, HEADER_LENGTH, MAGIC,
};
use crate::record::{self, Positioned};
use crate::registration::{
    DefinitionRef, Facts, Icon, IconRef, Projection, RegisteredCredential, RegisteredType, Version,
};

/// A registration the wallet wrote, open for reading. Opening reads its header, its directory
/// and its facts; each other part is read when a caller asks for it, and a definition or an
/// icon once.
#[derive(Debug)]
pub struct Registration<R> {
    blob: Blob<R>,
    version: Version,
    directory: Directory,
    entries: u32,
    facts: Facts,
    definitions: Vec<Cached<DefinitionRef, Projected>>,
    icons: Vec<Cached<IconRef, Icon>>,
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

/// An index entry read: its type and the span of its records.
struct IndexEntry {
    key: RegisteredType,
    records: Span<RecordsPart>,
}

/// The types of the entries a search read on either side of the type it looks for: every entry
/// it reads next sorts between them.
#[derive(Default)]
struct Fences {
    below: Option<RegisteredType>,
    above: Option<RegisteredType>,
}

impl<R: Read + Seek> Registration<R> {
    /// The registration of `source`: [`Version::CURRENT`] of the layout of
    /// `docs/registration.md`. Reads the header, the directory and the facts.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: the first rule they break, the magic number first.
    pub fn open(source: R) -> Result<Self, RegistrationError> {
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
        let entries = directory
            .index_entries()
            .map_err(|length| RegistrationError::IndexLength(ByteCount::new(length.into())))?;
        let bytes = blob.read_cbor(&directory.facts, directory.facts.whole())?;
        let item = cbor::decode(&bytes)
            .map_err(|error| RegistrationError::Facts(FactsFault::Cbor(error)))?;
        let facts = record::facts(&item, &directory.icons).map_err(RegistrationError::Facts)?;
        Ok(Self {
            blob,
            version,
            directory,
            entries,
            facts,
            definitions: Vec::new(),
            icons: Vec::new(),
        })
    }

    /// The format version.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The facts every request reads.
    pub fn facts(&self) -> &Facts {
        &self.facts
    }

    /// The credentials of the types of `types`, in the wallet's order. Reads, for each type once,
    /// the index entries a binary search visits, then the type's records when the index lists
    /// it.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: an index entry or a record that breaks a rule, an index out of
    /// order on a search's path, records of a type out of the wallet's order, or two
    /// credentials with one position, `credentialId` or batch.
    pub fn credentials(
        &mut self,
        types: &[RegisteredType],
    ) -> Result<Vec<RegisteredCredential>, RegistrationError> {
        let mut runs = Vec::new();
        for (at, key) in types.iter().enumerate() {
            if types.iter().take(at).any(|earlier| earlier == key) {
                continue;
            }
            if let Some(records) = self.find(key)? {
                runs.push(self.records(key, records)?);
            }
        }
        in_wallet_order(runs)
    }

    /// The definition `at` spans, projected to the wallet's language. `at` is a span a credential
    /// of this registration gave.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::Definition`]: no UTF-8, no projection, or another language; or a
    /// span past the blob.
    pub fn definition(&mut self, at: DefinitionRef) -> Result<Projected, RegistrationError> {
        if let Some(read) = self.definitions.iter().find(|read| read.at == at) {
            return Ok(read.part.clone());
        }
        let bytes = self.blob.read(&self.directory.definitions, at.span())?;
        let refused = |fault| RegistrationError::Definition(at, fault);
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

    /// The icon `at` spans. `at` is a span the facts or a credential of this registration gave.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: a span past the blob, or a source that fails.
    pub fn icon(&mut self, at: IconRef) -> Result<Icon, RegistrationError> {
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

    /// The whole registration: every index entry, in order, and every record, definition and
    /// icon.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: the first part that breaks a rule, an index entry that does not
    /// sort after the one before it.
    pub fn projection(&mut self) -> Result<Projection, RegistrationError> {
        let mut runs = Vec::new();
        let mut previous: Option<RegisteredType> = None;
        for at in 0..self.entries {
            let entry = self.entry(at)?;
            if previous.as_ref().is_some_and(|before| *before >= entry.key) {
                return Err(order(at));
            }
            runs.push(self.records(&entry.key, entry.records)?);
            previous = Some(entry.key);
        }
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

    /// The span of the records of `key`, when the index lists it: a binary search over the
    /// index entries, each entry it reads checked against the entries read before it.
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "low < high ≤ the entry count, a u32, inside the loop: high − low, the middle \
                  and the position after it stay within u32"
    )]
    fn find(
        &mut self,
        key: &RegisteredType,
    ) -> Result<Option<Span<RecordsPart>>, RegistrationError> {
        let mut low = 0;
        let mut high = self.entries;
        let mut fences = Fences::default();
        while low < high {
            let at = low + (high - low) / 2;
            let entry = self.entry(at)?;
            if !fences.admit(&entry.key) {
                return Err(order(at));
            }
            match entry.key.cmp(key) {
                Ordering::Less => {
                    low = at + 1;
                    fences.below = Some(entry.key);
                }
                Ordering::Greater => {
                    high = at;
                    fences.above = Some(entry.key);
                }
                Ordering::Equal => return Ok(Some(entry.records)),
            }
        }
        Ok(None)
    }

    /// The index entry at `at`, with its type's name.
    fn entry(&mut self, at: u32) -> Result<IndexEntry, RegistrationError> {
        let refused = |fault| RegistrationError::Index(key_index(at), fault);
        let span = self
            .directory
            .index_entry(at)
            .map_err(|error| refused(IndexFault::Span(error)))?;
        let words: EntryWords = self.blob.words(self.directory.index.start_of(span))?;
        let entry = RawEntry::parse(&words, &self.directory).map_err(refused)?;
        let name = self.blob.read(&self.directory.names, entry.name)?;
        let name = std::str::from_utf8(&name).map_err(|e| refused(IndexFault::Name(e)))?;
        if name.is_empty() {
            return Err(refused(IndexFault::NameEmpty));
        }
        Ok(IndexEntry {
            key: RegisteredType::new(entry.format, name),
            records: entry.records,
        })
    }

    /// The credentials the records of `key` at `span` hold: a CBOR sequence of records, in the
    /// wallet's order.
    fn records(
        &mut self,
        key: &RegisteredType,
        span: Span<RecordsPart>,
    ) -> Result<Vec<Positioned>, RegistrationError> {
        let bytes = self.blob.read_cbor(&self.directory.records, span)?;
        let items = cbor::decode_sequence(&bytes)
            .map_err(|error| RegistrationError::Records(key.clone(), error))?;
        let mut records: Vec<Positioned> = Vec::new();
        for (at, item) in items.iter().enumerate() {
            let record = RecordIndex::new(at);
            let read = record::credential(item, key, &self.directory).map_err(|fault| {
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
}

impl<R: Read + Seek> Blob<R> {
    /// The blob of `source`, its length the end `source` seeks to.
    fn of(mut source: R) -> Result<Self, RegistrationError> {
        let length = source.seek(SeekFrom::End(0))?;
        Ok(Self { source, length })
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
        let at = bounds.start_of(span);
        let length = span.length();
        self.within(at, length.into())?;
        // A buffer holds at most isize::MAX bytes. Below that, `vec!` aborts when the platform
        // has no memory for the part, and allocates it otherwise.
        let size = isize::try_from(length)
            .ok()
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(RegistrationError::TooLong(ByteCount::new(length.into())))?;
        let mut bytes = vec![0; size];
        self.fill(at, &mut bytes)?;
        Ok(bytes)
    }

    /// The bytes `span` spans in `bounds`, a CBOR part.
    ///
    /// # Errors
    ///
    /// [`RegistrationError::TooLong`] for a part longer than [`cbor::MAX_INPUT`], which the
    /// CBOR reader refuses: the bytes stay unread.
    fn read_cbor<S: Part>(
        &mut self,
        bounds: &Bounds<S>,
        span: Span<S>,
    ) -> Result<Vec<u8>, RegistrationError> {
        let length = span.length();
        if usize::try_from(length).map_or(true, |length| length > cbor::MAX_INPUT) {
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

    /// Checks that the `length` bytes at `at` lie within the blob: a span another
    /// registration gave may lie past it.
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

impl Fences {
    /// Whether `key` sorts strictly between the fences.
    fn admit(&self, key: &RegisteredType) -> bool {
        self.below.as_ref().is_none_or(|below| below < key)
            && self.above.as_ref().is_none_or(|above| key < above)
    }
}

/// The refusal of the index entry at `at`, out of order.
fn order(at: u32) -> RegistrationError {
    RegistrationError::Index(key_index(at), IndexFault::Order)
}

/// The index position `at`, as errors name it.
fn key_index(at: u32) -> KeyIndex {
    // A u32 fits the usize of every target the crate builds for.
    KeyIndex::new(at as usize)
}

/// The credentials of `runs`, each the records of one type in the wallet's order, merged into
/// that order.
///
/// # Errors
///
/// [`RegistrationError::PositionRepeated`] and [`RegistrationError::EntryRepeated`].
fn in_wallet_order(
    runs: Vec<Vec<Positioned>>,
) -> Result<Vec<RegisteredCredential>, RegistrationError> {
    let mut ordered: Vec<RegisteredCredential> = Vec::new();
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
fn merge(first: Vec<Positioned>, second: Vec<Positioned>) -> Vec<Positioned> {
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
