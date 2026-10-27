//! The CBOR form of a registration's parts: maps with text keys, and the claims path pointers,
//! entry references, trust store authorities and served-type reasons they carry.

#[cfg(feature = "wallet")]
use siros_codec::cbor::Value as Cbor;
use siros_codec::cbor::{Item, Kind};
use siros_codec::member::MemberFault;
use siros_credential::EntryRef;
use siros_dcql::{AuthorityValue, ClaimPath, ClaimPathError, ComponentIndex, PathComponent};
use siros_transaction_data::{CredentialSource, Unserved};
use siros_trust::{StoreAuthority, StoreType};
use siros_wallet_state::{BatchId, CredentialId, InstanceId};

use crate::error::{CredentialFault, Member, RegistrationError};

impl Member {
    /// The member's name in the registration's CBOR.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::RegisteredAt => "registered_at",
            Self::Language => "language",
            Self::Diagnostics => "diagnostics",
            Self::Systems => "systems",
            Self::Icons => "icons",
            Self::DefaultIcon => "default_icon",
            Self::Definitions => "definitions",
            Self::Credentials => "credentials",
            Self::Entry => "entry",
            Self::Format => "format",
            Self::Type => "type",
            Self::Key => "key",
            Self::Claims => "claims",
            Self::Card => "card",
            Self::Title => "title",
            Self::Issuer => "issuer",
            Self::Icon => "icon",
            Self::Labels => "labels",
            Self::TypeLabels => "types",
            Self::IssuerLabels => "configuration",
            Self::Background => "background",
            Self::Trust => "trust",
            Self::KeyIdentifiers => "aki",
            Self::Admitting => "admitting",
            Self::Transactions => "transactions",
            Self::ServedTypes => "served",
            Self::Otherwise => "otherwise",
        }
    }
}

/// A member that is absent or of the wrong type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Malformed(pub(crate) Member, pub(crate) MemberFault);

impl From<Malformed> for RegistrationError {
    fn from(Malformed(member, fault): Malformed) -> Self {
        Self::Member(member, fault)
    }
}

impl From<Malformed> for CredentialFault {
    fn from(Malformed(member, fault): Malformed) -> Self {
        Self::Member(member, fault)
    }
}

/// A CBOR map of a registration, read by member.
#[derive(Clone, Copy)]
pub(crate) struct Map<'a, 'i>(&'a [(Item<'i>, Item<'i>)]);

impl<'a, 'i> Map<'a, 'i> {
    /// The map `item` holds.
    pub(crate) fn of(item: &'a Item<'i>) -> Result<Self, MemberFault> {
        item.as_map().map(Self).ok_or(MemberFault::WrongType)
    }

    /// The first key of the map outside `known`.
    pub(crate) fn unknown(self, known: &[Member]) -> Option<String> {
        self.0.iter().find_map(|(key, _)| match key.as_text() {
            Some(name) if known.iter().any(|member| member.name() == name) => None,
            Some(name) => Some(name.to_owned()),
            None => Some(String::new()),
        })
    }

    /// The member `member`, when the map has it.
    pub(crate) fn optional(self, member: Member) -> Option<&'a Item<'i>> {
        self.0
            .iter()
            .find(|(key, _)| key.as_text() == Some(member.name()))
            .map(|(_, value)| value)
    }

    /// The member `member`.
    pub(crate) fn require(self, member: Member) -> Result<&'a Item<'i>, Malformed> {
        self.optional(member)
            .ok_or(Malformed(member, MemberFault::Absent))
    }

    /// The member `member`, read by `read`, which refuses its type.
    pub(crate) fn read<T>(
        self,
        member: Member,
        read: impl FnOnce(&'a Item<'i>) -> Option<T>,
    ) -> Result<T, Malformed> {
        read(self.require(member)?).ok_or(Malformed(member, MemberFault::WrongType))
    }
}

/// An unsigned integer.
pub(crate) fn unsigned(item: &Item<'_>) -> Option<u64> {
    match item.kind() {
        Kind::Unsigned(n) => Some(*n),
        _ => None,
    }
}

/// A boolean.
pub(crate) fn boolean(item: &Item<'_>) -> Option<bool> {
    match item.kind() {
        Kind::Bool(b) => Some(*b),
        _ => None,
    }
}

/// The entry `[credentialId, batchId, instanceId]`.
pub(crate) fn entry(item: &Item<'_>) -> Option<EntryRef> {
    match item.as_array()? {
        [credential, batch, instance] => Some(EntryRef::new(
            CredentialId::new(unsigned(credential)?),
            BatchId::new(unsigned(batch)?),
            InstanceId::new(unsigned(instance)?),
        )),
        _ => None,
    }
}

/// The claims path pointer of an array of keys, indexes and `null`s.
pub(crate) fn path(item: &Item<'_>) -> Result<ClaimPath, ClaimPathError> {
    let components = item.as_array().ok_or(ClaimPathError::NotArray)?;
    let components = components
        .iter()
        .enumerate()
        .map(|(at, component)| match component.kind() {
            Kind::Text(key) => Ok(PathComponent::Key((*key).to_owned())),
            Kind::Unsigned(index) => Ok(PathComponent::Index(*index)),
            Kind::Null => Ok(PathComponent::Null),
            _ => Err(ClaimPathError::Component(ComponentIndex::new(at))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    ClaimPath::new(components)
}

/// The trust store authority `[type, value]`.
pub(crate) fn authority(item: &Item<'_>) -> Result<StoreAuthority, CredentialFault> {
    let malformed = CredentialFault::Member(Member::Admitting, MemberFault::WrongType);
    let [kind, value] = item.as_array().ok_or(malformed.clone())? else {
        return Err(malformed);
    };
    let (Some(kind), Some(value)) = (kind.as_text(), value.as_text()) else {
        return Err(malformed);
    };
    let kind = StoreType::named(kind).ok_or_else(|| CredentialFault::StoreType(kind.to_owned()))?;
    Ok(StoreAuthority::new(kind, AuthorityValue::new(value)))
}

/// Every reason a registration records.
const UNSERVED: [Unserved; 10] = [
    Unserved::Format,
    Unserved::TypeUnsupported,
    Unserved::TypeUndeclared,
    Unserved::IssuerMetadataNotHeld,
    Unserved::CredentialMetadata,
    Unserved::TypeMetadata,
    Unserved::Definition(CredentialSource::CredentialMetadata),
    Unserved::Definition(CredentialSource::TypeMetadata),
    Unserved::Definition(CredentialSource::Configuration),
    Unserved::Language,
];

/// The name a registration writes for `reason`.
fn unserved_name(reason: Unserved) -> &'static str {
    match reason {
        Unserved::Format => "format",
        Unserved::TypeUnsupported => "type_unsupported",
        Unserved::TypeUndeclared => "type_undeclared",
        Unserved::IssuerMetadataNotHeld => "issuer_metadata_not_held",
        Unserved::CredentialMetadata => "credential_metadata",
        Unserved::TypeMetadata => "type_metadata",
        Unserved::Definition(CredentialSource::CredentialMetadata) => {
            "definition_credential_metadata"
        }
        Unserved::Definition(CredentialSource::TypeMetadata) => "definition_type_metadata",
        Unserved::Definition(CredentialSource::Configuration) => "definition_configuration",
        Unserved::Language => "language",
    }
}

/// The reason a text names.
pub(crate) fn unserved(item: &Item<'_>) -> Result<Unserved, CredentialFault> {
    let name = item.as_text().ok_or(CredentialFault::Member(
        Member::ServedTypes,
        MemberFault::WrongType,
    ))?;
    UNSERVED
        .into_iter()
        .find(|reason| unserved_name(*reason) == name)
        .ok_or_else(|| CredentialFault::UnservedUnknown(name.to_owned()))
}

/// The writers of the parts above.
#[cfg(feature = "wallet")]
pub(crate) mod write {
    use super::*;

    /// The map of `members`.
    pub(crate) fn map(members: impl IntoIterator<Item = (Member, Cbor)>) -> Cbor {
        Cbor::Map(
            members
                .into_iter()
                .map(|(member, value)| (Cbor::text(member.name()), value))
                .collect(),
        )
    }

    /// `[credentialId, batchId, instanceId]`.
    pub(crate) fn entry(entry: EntryRef) -> Cbor {
        Cbor::Array(vec![
            Cbor::Unsigned(entry.credential_id().value()),
            Cbor::Unsigned(entry.batch_id().value()),
            Cbor::Unsigned(entry.instance_id().value()),
        ])
    }

    /// The pointer's components: keys, indexes and `null`s.
    pub(crate) fn path(path: &ClaimPath) -> Cbor {
        Cbor::Array(
            path.components()
                .iter()
                .map(|component| match component {
                    PathComponent::Key(key) => Cbor::text(key),
                    PathComponent::Index(index) => Cbor::Unsigned(*index),
                    PathComponent::Null => Cbor::Null,
                })
                .collect(),
        )
    }

    /// `[type, value]`.
    pub(crate) fn authority(authority: &StoreAuthority) -> Cbor {
        Cbor::Array(vec![
            Cbor::text(authority.kind().as_str()),
            Cbor::text(authority.value().as_str()),
        ])
    }

    /// The name of `reason`.
    pub(crate) fn unserved(reason: Unserved) -> Cbor {
        Cbor::text(unserved_name(reason))
    }
}
