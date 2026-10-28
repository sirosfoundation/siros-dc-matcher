//! Why bytes are no registration, and why the wallet's state gives none.

use std::io;
use std::str::Utf8Error;

use siros_codec::cbor::CborError;
use siros_codec::member::MemberFault;
use siros_credential::TreeError;
use siros_dcql::ClaimPathError;
use siros_display::{LocaleError, TextError};
use siros_transaction_data::{EmptyTypeId, ProjectionError, TypeRepeated};
use siros_trust::KeyIdentifierError;

use crate::ids::{CredentialIndex, KeyIndex, RecordIndex};
use crate::layout::SectionKind;
use crate::registration::{DefinitionRef, RegisteredType};

/// A member of a registration's facts, or of a credential record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    /// `registered_at`: the time the registration's facts hold at.
    RegisteredAt,
    /// `language`: the wallet's language.
    Language,
    /// `diagnostics`.
    Diagnostics,
    /// `systems`: the nym_auth systems the wallet proves.
    Systems,
    /// `verifier_id`: the form of the nym_auth `verifier_id` the wallet's trust framework fixes.
    VerifierId,
    /// `default_icon`: the span of the wallet's icon, which a picker entry without a credential
    /// shows.
    DefaultIcon,
    /// A record's `position`: the credential's position in the wallet's order.
    Position,
    /// A record's `entry`: `[credentialId, batchId, instanceId]`.
    Entry,
    /// A record's `key`: whether the wallet holds the key the credential is bound to.
    Key,
    /// A record's `claims`.
    Claims,
    /// A record's `card`.
    Card,
    /// A card's `title`.
    Title,
    /// A card's `issuer`.
    Issuer,
    /// A card's `icon`: the span of its icon.
    Icon,
    /// A record's `labels`.
    Labels,
    /// The labelled descriptions of the Type Metadata.
    TypeLabels,
    /// The descriptions of the configuration.
    IssuerLabels,
    /// A record's `background`: whether the credential is presentable without the wallet's UI.
    Background,
    /// A record's `trust`: the issuer facts.
    Trust,
    /// The AuthorityKeyIdentifier keyIdentifiers of the issuer facts.
    KeyIdentifiers,
    /// The trust store authorities that admit the issuer.
    Admitting,
    /// A record's `transactions`.
    Transactions,
    /// What the sources serve for each type they name.
    ServedTypes,
    /// Why no definition serves any other type.
    Otherwise,
}

/// A count of bytes: a length, or an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteCount(u64);

impl ByteCount {
    /// The count `bytes`.
    pub(crate) const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// What a span lies in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Within {
    /// The blob.
    Blob,
    /// A section.
    Section(SectionKind),
}

/// A span that ends past the part it lies in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("registration_out_of_bounds")]
pub struct OutOfBounds {
    /// The part.
    pub within: Within,
    /// Where the span starts, from the part's start.
    pub offset: ByteCount,
    /// The span's length.
    pub length: ByteCount,
    /// The part's length.
    pub limit: ByteCount,
}

impl OutOfBounds {
    pub(crate) fn new(within: Within, offset: u64, length: u64, limit: u64) -> Self {
        Self {
            within,
            offset: ByteCount::new(offset),
            length: ByteCount::new(length),
            limit: ByteCount::new(limit),
        }
    }
}

/// Why a directory is no directory of [`crate::Version::CURRENT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("registration_directory")]
pub enum DirectoryFault {
    /// The entry where the version lists this section has another code.
    Kind {
        /// The section the version lists.
        expected: SectionKind,
        /// The code the entry has.
        found: u32,
    },
    /// The section starts at this offset, elsewhere than where the part before it ends.
    Offset {
        /// The section.
        kind: SectionKind,
        /// Its offset.
        offset: u32,
    },
    /// The last section ends here, before the blob's end.
    Trailing {
        /// Where it ends.
        end: ByteCount,
    },
}

/// Why the facts section is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum FactsFault {
    /// The section is no CBOR item the reader accepts.
    Cbor(#[source] CborError),
    /// The item is no map.
    NotMap,
    /// A member is absent or of the wrong type.
    Member(Member, #[source] MemberFault),
    /// The facts have this member, which they do not define.
    MemberUnknown(String),
    /// `registered_at` is no `tdate`.
    RegisteredAt,
    /// `language` is no language tag.
    Language(#[source] LocaleError),
    /// `systems` names this system, which the picker does not know.
    System(String),
    /// `verifier_id` names this form, which the picker does not know.
    VerifierIdForm(String),
    /// `default_icon` ends past the icons section.
    DefaultIcon(#[source] OutOfBounds),
    /// `default_icon` spans no byte.
    DefaultIconEmpty,
}

/// Why an index entry is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum IndexFault {
    /// The entry has this format code, which is neither 1 (`dc+sd-jwt`) nor 2 (`mso_mdoc`).
    Format(u32),
    /// The span of the name or of the records ends past its section.
    Span(#[source] OutOfBounds),
    /// The name is no UTF-8.
    Name(#[source] Utf8Error),
    /// The name is the empty string: no `vct` or `docType` is.
    NameEmpty,
    /// The entry's type does not sort between the types of the entries read before it in the
    /// same search: the index is out of order.
    Order,
}

/// Why a credential record is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum CredentialFault {
    /// The record is no map.
    NotMap,
    /// A member is absent or of the wrong type.
    Member(Member, #[source] MemberFault),
    /// The record has this member, which it does not define.
    MemberUnknown(String),
    /// `claims` is no claim tree.
    Claims(#[source] TreeError),
    /// A label, or the card's title or issuer, is no safe label.
    Text(#[source] TextError),
    /// A label's path is no claims path pointer.
    Path(#[source] ClaimPathError),
    /// An AuthorityKeyIdentifier keyIdentifier is empty.
    KeyIdentifier(#[source] KeyIdentifierError),
    /// An admitting authority names this `type`, which is no trust store type.
    StoreType(String),
    /// A served type is the empty string.
    TypeId(EmptyTypeId),
    /// A served type is named twice.
    TypeRepeated(#[source] TypeRepeated),
    /// A span of this member ends past its section.
    Span(Member, #[source] OutOfBounds),
    /// The card's icon spans no byte.
    IconEmpty,
    /// A served type's reason is none a registration records.
    UnservedUnknown(String),
}

/// Why a definition is refused.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{}", self.code())]
pub enum DefinitionFault {
    /// Its bytes are no UTF-8.
    Utf8(#[source] Utf8Error),
    /// Its text is no projection.
    Projection(#[source] ProjectionError),
    /// It is projected to another language than the registration's.
    Language,
}

/// Why bytes are no registration this picker reads.
#[derive(Debug, thiserror::Error)]
#[error("{}", self.code())]
pub enum RegistrationError {
    /// The source gave an error.
    Read(#[from] io::Error),
    /// The blob starts with other bytes than the magic number.
    Magic,
    /// The registration has this version; the reader reads [`crate::Version::CURRENT`].
    Version(u32),
    /// The header, the directory or a section ends past the blob.
    OutOfBlob(#[source] OutOfBounds),
    /// The directory breaks a rule.
    Directory(#[source] DirectoryFault),
    /// The facts break a rule.
    Facts(#[source] FactsFault),
    /// The index section has this length, which is no multiple of an entry's 20 bytes.
    IndexLength(ByteCount),
    /// The index entry at this position breaks a rule.
    Index(KeyIndex, #[source] IndexFault),
    /// The records of this type are no CBOR sequence.
    Records(RegisteredType, #[source] CborError),
    /// A record of a type has a position at or before the record ahead of it: the records of
    /// a type follow the wallet's order.
    RecordOrder {
        /// The type the index files the record under.
        credential_type: RegisteredType,
        /// The record's position among the records of its type.
        record: RecordIndex,
    },
    /// A record of a type breaks a rule.
    Credential {
        /// The type the index files the record under.
        credential_type: RegisteredType,
        /// The record's position among the records of its type.
        record: RecordIndex,
        /// The rule it breaks.
        #[source]
        fault: CredentialFault,
    },
    /// Two records read have this position.
    PositionRepeated(CredentialIndex),
    /// The credential at this position has the `credentialId` or the batch of a credential read
    /// with it.
    EntryRepeated(CredentialIndex),
    /// The definition of this span breaks a rule.
    Definition(DefinitionRef, #[source] DefinitionFault),
    /// A part of this many bytes, more than the reader holds: an icon past `isize::MAX`, the
    /// most a buffer of the platform holds, the facts or the records of a type past
    /// [`siros_codec::cbor::MAX_INPUT`], and a definition past
    /// [`siros_codec::json::MAX_TEXT`], the most the CBOR and the JSON reader decode.
    TooLong(ByteCount),
}

impl RegistrationError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Read(_) => "registration_unreadable",
            Self::Magic => "registration_magic",
            Self::Version(_) => "registration_version",
            Self::OutOfBlob(_) => "registration_out_of_bounds",
            Self::Directory(_) => "registration_directory",
            Self::Facts(fault) => fault.code(),
            Self::IndexLength(_) => "registration_index_length",
            Self::Index(_, fault) => fault.code(),
            Self::Records(_, error) => error.code(),
            Self::RecordOrder { .. } => "registration_record_order",
            Self::Credential { fault, .. } => fault.code(),
            Self::PositionRepeated(_) => "registration_position_repeated",
            Self::EntryRepeated(_) => "registration_entry_repeated",
            Self::Definition(_, fault) => fault.code(),
            Self::TooLong(_) => "registration_too_long",
        }
    }
}

impl FactsFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cbor(error) => error.code(),
            Self::NotMap | Self::Member(..) | Self::MemberUnknown(_) | Self::RegisteredAt => {
                "registration_malformed"
            }
            Self::Language(error) => error.code(),
            Self::System(_) => "registration_system_unknown",
            Self::VerifierIdForm(_) => "registration_verifier_id_form_unknown",
            Self::DefaultIcon(_) => "registration_out_of_bounds",
            Self::DefaultIconEmpty => "registration_icon_empty",
        }
    }
}

impl IndexFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Format(_) => "registration_format_unknown",
            Self::Span(_) => "registration_out_of_bounds",
            Self::Name(_) => "registration_type_not_utf8",
            Self::NameEmpty => "registration_credential_type_empty",
            Self::Order => "registration_index_order",
        }
    }
}

impl CredentialFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotMap | Self::Member(..) | Self::MemberUnknown(_) | Self::UnservedUnknown(_) => {
                "registration_credential_malformed"
            }
            Self::Claims(error) => error.code(),
            Self::Text(error) => error.code(),
            Self::Path(error) => error.code(),
            Self::KeyIdentifier(error) => error.code(),
            Self::StoreType(_) => "registration_store_type_unknown",
            Self::TypeId(_) => "registration_type_empty",
            Self::TypeRepeated(error) => error.code(),
            Self::Span(..) => "registration_out_of_bounds",
            Self::IconEmpty => "registration_icon_empty",
        }
    }
}

impl DefinitionFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Utf8(_) => "registration_definition_not_utf8",
            Self::Projection(error) => error.code(),
            Self::Language => "registration_definition_language",
        }
    }
}
