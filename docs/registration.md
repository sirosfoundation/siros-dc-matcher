# The registration format

The registration is the blob the wallet registers with Credential Manager beside
`matcher.wasm`. `siros_registration::write` writes it; `siros_registration::Registration` reads
it through `std::io::Read + Seek`. The picker reads the parts a request needs through
`android_credman::CredentialReader`, each at its offset with `ReadCredentialsBuffer`:

1. the header, the directory and the facts, when it opens the registration;
2. the index entries a binary search visits, for each credential type the request's queries
   ask for;
3. the records of those types;
4. the definitions the request's transaction data entries name for those credentials;
5. the icons of the entries it emits.

This document describes version 1.

## Layout

Every integer of the layout is an unsigned 32-bit little-endian number. An offset counts bytes
from the start of the blob in the directory, and from the start of its section everywhere
else.

| Part | Offset | Bytes | Contents |
|---|---|---|---|
| Header | 0 | 12 | The magic number `89 53 52 47 0D 0A 1A 0A`, then the version, 1 |
| Directory | 12 | 72 | Six entries of 12 bytes: kind, offset, length |
| Sections | 84 | the rest | The six sections, in the directory's order |

### Directory

| Kind | Section | Contents |
|---|---|---|
| 1 | Facts | One CBOR map: what every request reads |
| 2 | Index | One entry of 20 bytes per credential type |
| 3 | Names | The types' names, UTF-8 |
| 4 | Records | The credential records, those of a type together as one CBOR sequence (RFC 8742) |
| 5 | Definitions | The projected transaction data definitions, each a JSON text |
| 6 | Icons | The icons' bytes |

The directory lists the six kinds in this order. The first section starts at 84, each next one
where the one before it ends, and the last one ends at the end of the blob. A later version
adds a section as a new kind, with its own version number.

### Index

An index entry is five numbers:

| Bytes | Field |
|---|---|
| 0–3 | The format: 1 for `dc+sd-jwt`, 2 for `mso_mdoc` |
| 4–7 | The offset of the type's name in the names section |
| 8–11 | The length of the name: at least one byte |
| 12–15 | The offset of the type's records in the records section |
| 16–19 | The length of the records |

The entries are sorted by format, then by the bytes of the name, each type once. The reader
finds a type by binary search over the range `[low, high)` of entries, from `[0, count)`: it
reads the entry at `low + (high − low) / 2`, rounded down, and its name, and keeps the half
that can hold the type. Each entry a search reads must sort after every entry the search read
below it and before every entry it read above it.

### Spans

A record names its icon and its definitions by span: the CBOR array `[offset, length]`, offset
from the start of the icons or the definitions section. A span ends within its section, and an
icon's span holds at least one byte. Records name a definition or an icon they share by one
span: each distinct definition and icon is stored once.

### Facts

| Member | Value |
|---|---|
| `registered_at` | Tag 0 over a `tdate`: the time the registration's facts hold at |
| `language` | The wallet's language tag, which every card, label and definition is in |
| `diagnostics` | Whether the picker shows an entry that names why a request has no offer |
| `systems` | The ids of the nym_auth systems the wallet proves, in its order of preference |
| `verifier_id` | The form of the nym_auth `verifier_id`: `x509_san_dns` or `semantic` |
| `default_icon` | The span of the wallet's icon, which an entry without an icon of its own shows |

### Records

The records of a type are CBOR maps, one after another in the wallet's order. The index entry
gives the type and its format.

| Member | Value |
|---|---|
| `position` | The credential's position in the wallet's order, distinct for each record |
| `entry` | `[credentialId, batchId, instanceId]`: each `credentialId` and each batch once |
| `key` | Whether the wallet holds the key the credential is bound to |
| `claims` | The claim tree (`siros_credential::ClaimTree::to_cbor`) |
| `card` | `{title, issuer, icon}`: the title and issuer line in the wallet's language, and the icon's span |
| `labels` | `{types, configuration}`: claim descriptions, each `[path]` or `[path, label]` |
| `background` | Whether the wallet presents the credential without its UI (A9) |
| `trust` | `{aki, admitting}`: the issuer facts at registration (TR5) |
| `transactions` | `{served, otherwise}`: each transaction data type with the span of its definition or the reason none serves it, and the reason for every other type |

A definition is the JSON text of `siros_transaction_data::Projected`, in the facts' language.

## Reading

The reader refuses, with a `RegistrationError` that names the part and the cause:

- a blob that does not start with the magic number;
- every version but 1;
- a header, directory or section that ends past the blob, a directory that breaks its order or
  leaves bytes after the last section, a span that ends past its section, and a read that ends
  past the blob;
- an index whose length is no multiple of 20, an unknown format code, a name of no byte or no
  UTF-8, and an index entry that a search finds out of order;
- facts or a record that do not parse: no CBOR map, an absent or unknown member, a value of
  the wrong type;
- records of a type out of the wallet's order, and two records read with one position,
  `credentialId` or batch;
- a definition of no UTF-8, no projection, or another language than the facts';
- an icon longer than a buffer of the platform holds (`isize::MAX` bytes), facts or records of a
  type longer than `cbor::MAX_INPUT` of siros-codec (16,909,320 bytes on wasm32), and a definition
  longer than `json::MAX_TEXT` (10,275,041 bytes on wasm32).

The reader reads a part into a buffer of the part's length, which lies within the blob.
Decoding a CBOR part allocates at most `cbor::HEAP_PER_BYTE` bytes per byte of it: 127 on wasm32
and 243 on a 64-bit target. A vector of items grows as they decode, from four slots, and a map
keeps a hash set of its keys. Reading a definition allocates at most `json::HEAP_PER_BYTE` bytes
per byte: 209 on wasm32 and 241 on a 64-bit target. The values of a part thus take at most
`isize::MAX` bytes.

## Writing

`siros_registration::encode` lays a `Projection` out; `write` projects the wallet's state, then
encodes it. `project` refuses a credential whose `vct` or `docType` is empty
(`WriteError::TypeEmpty`): a type's name in the index holds at least one byte. Equal projections give equal bytes: the CBOR is deterministic (RFC 8949, Section
4.2.1), the index is sorted, the records of a type keep the wallet's order, and each icon and
definition takes the place of its first use, the facts' icon first.

## Prior art

The layout is a header and directory container with a sorted fixed-width index and
length-delimited records.

- **SQLite** puts a magic string and its version numbers at offset 0 of a fixed header, and
  refuses a file whose read version is above the one it knows. The registration does the same
  with an exact version. For files from untrusted sources SQLite turns on checks of each page's
  cell offsets as it reads the page (`PRAGMA cell_size_check`); here every offset becomes a span
  only through the check against its part.
- **SSTable** (LevelDB) finds a key by binary search over a sorted index block, whose entries
  hold block handles. The registration's index is that block, with fixed-width entries and the
  handles of the records. A reader that trusts the order misses keys silently, so the reader
  checks each entry it reads against the ones read before it in the same search.
- **zip** keeps a central directory of offsets beside the local headers. Readers that trust
  different copies read different files, and overlapping entries make zip bombs. The
  registration states each fact once, and its sections tile the blob.
- **FlatBuffers and Cap'n Proto** address data by offsets inside one buffer. Their verifiers
  check every offset against the buffer, and cap nesting and traversal against amplification.
  Here the items of a CBOR part take at most `cbor::HEAP_PER_BYTE` bytes per byte of it, and
  CBOR nesting stops at the codec's depth.
- **CBOR sequences** (RFC 8742) frame only their items: a sequence cut between two items reads
  as a whole one. The index gives each sequence its exact length, and the reader decodes it to
  the last byte.
- A **hash index** (FxHash buckets, a constant database) needs a hash function every writer and
  reader compute alike. FxHash gives one result on 32-bit `wasm32` and another on a 64-bit
  wallet, so the index is sorted.
