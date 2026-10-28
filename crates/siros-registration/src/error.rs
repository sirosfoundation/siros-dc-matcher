//! Why bytes are no registration, and why the wallet's state gives none.

use siros_codec::cbor::CborError;
use siros_codec::member::MemberFault;
use siros_credential::TreeError;
use siros_dcql::ClaimPathError;
use siros_display::{LocaleError, TextError};
use siros_transaction_data::{EmptyTypeId, ProjectionError, TypeRepeated};
use siros_trust::KeyIdentifierError;

use crate::ids::{CredentialIndex, DefinitionIndex, IconIndex};

/// A member of a registration, or of one of its credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    /// `version`.
    Version,
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
    /// `icons`.
    Icons,
    /// `default_icon`: the position of the wallet's icon, which a picker entry without a
    /// credential shows.
    DefaultIcon,
    /// `definitions`: the projected transaction data definitions.
    Definitions,
    /// `credentials`.
    Credentials,
    /// A credential's `entry`: `[credentialId, batchId, instanceId]`.
    Entry,
    /// A credential's `format`.
    Format,
    /// A credential's `type`.
    Type,
    /// A credential's `key`: whether the wallet holds the key it is bound to.
    Key,
    /// A credential's `claims`.
    Claims,
    /// A credential's `card`.
    Card,
    /// A card's `title`.
    Title,
    /// A card's `issuer`.
    Issuer,
    /// A card's `icon`.
    Icon,
    /// A credential's `labels`.
    Labels,
    /// The labelled descriptions of the Type Metadata.
    TypeLabels,
    /// The descriptions of the configuration.
    IssuerLabels,
    /// A credential's `background`: whether it is presentable without the wallet's UI.
    Background,
    /// A credential's `trust`: its issuer facts.
    Trust,
    /// The AuthorityKeyIdentifier keyIdentifiers of the issuer facts.
    KeyIdentifiers,
    /// The trust store authorities that admit the issuer.
    Admitting,
    /// A credential's `transactions`.
    Transactions,
    /// What the sources serve for each type they name.
    ServedTypes,
    /// Why no definition serves any other type.
    Otherwise,
}

/// Why bytes are no registration this picker reads.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum RegistrationError {
    /// The bytes are no CBOR item the reader accepts.
    Cbor(#[source] CborError),
    /// The item is no map.
    NotMap,
    /// The registration has this version; the picker reads its own.
    Version(u64),
    /// A member of the registration is absent or of the wrong type.
    Member(Member, MemberFault),
    /// The registration has this member, which it does not define.
    MemberUnknown(String),
    /// `registered_at` is no `tdate`.
    RegisteredAt,
    /// `language` is no language tag.
    Language(#[source] LocaleError),
    /// `systems` names this system, which the picker does not know.
    System(String),
    /// `verifier_id` names this form, which the picker does not know.
    VerifierIdForm(String),
    /// The icon at this position has no byte.
    IconEmpty(IconIndex),
    /// `default_icon` names an icon at this position, which the registration lacks.
    DefaultIconUnknown(IconIndex),
    /// The definition at this position is no projection.
    Definition(DefinitionIndex, #[source] ProjectionError),
    /// The definition at this position is projected to another language than the
    /// registration's.
    DefinitionLanguage(DefinitionIndex),
    /// The credential at this position breaks a rule.
    Credential(CredentialIndex, #[source] CredentialFault),
    /// Two credentials have this `credentialId`, or are instances of one batch.
    EntryRepeated(CredentialIndex),
}

/// Why a credential of a registration is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{}", self.code())]
pub enum CredentialFault {
    /// The credential is no map.
    NotMap,
    /// A member is absent or of the wrong type.
    Member(Member, MemberFault),
    /// The credential has this member, which it does not define.
    MemberUnknown(String),
    /// `format` names this format, which is neither `dc+sd-jwt` nor `mso_mdoc`.
    Format(String),
    /// `type` is the empty string: no `vct` or `docType` is.
    TypeEmpty,
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
    /// The card names an icon at this position, which the registration lacks.
    IconUnknown(IconIndex),
    /// A served type names a definition at this position, which the registration lacks.
    DefinitionUnknown(DefinitionIndex),
    /// A served type's reason is none a registration records.
    UnservedUnknown(String),
}

impl RegistrationError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Cbor(error) => error.code(),
            Self::NotMap => "registration_malformed",
            Self::Version(_) => "registration_version",
            Self::Member(..) | Self::MemberUnknown(_) | Self::RegisteredAt => {
                "registration_malformed"
            }
            Self::Language(error) => error.code(),
            Self::System(_) => "registration_system_unknown",
            Self::VerifierIdForm(_) => "registration_verifier_id_form_unknown",
            Self::IconEmpty(_) => "registration_icon_empty",
            Self::DefaultIconUnknown(_) => "registration_icon_unknown",
            Self::Definition(_, error) => error.code(),
            Self::DefinitionLanguage(_) => "registration_definition_language",
            Self::Credential(_, fault) => fault.code(),
            Self::EntryRepeated(_) => "registration_entry_repeated",
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
            Self::Format(_) => "registration_format_unknown",
            Self::TypeEmpty => "registration_credential_type_empty",
            Self::Claims(error) => error.code(),
            Self::Text(error) => error.code(),
            Self::Path(error) => error.code(),
            Self::KeyIdentifier(error) => error.code(),
            Self::StoreType(_) => "registration_store_type_unknown",
            Self::TypeId(_) => "registration_type_empty",
            Self::TypeRepeated(error) => error.code(),
            Self::IconUnknown(_) => "registration_icon_unknown",
            Self::DefinitionUnknown(_) => "registration_definition_unknown",
        }
    }
}
