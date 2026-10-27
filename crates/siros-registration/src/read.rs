//! The reading of a registration's CBOR, as the wallet writes it.

use siros_codec::cbor::{self, Item};
use siros_codec::date::DateTime;
use siros_codec::member::{ArrayIndex, MemberFault};
use siros_credential::{ClaimTree, Format};
use siros_dcql::{DocType, Vct};
use siros_display::{CardText, ClaimLabels, DescribedLabel, LabelText, Locale};
use siros_presentation::{KeyHolding, Presentability};
use siros_transaction_data::{Projected, ServedTypes, TypeId};
use siros_trust::{IssuerFacts, KeyIdentifier};
use siros_zkp_req::SystemId;
use siros_zkp_req_nym_auth::system::NymAuthSystem;

use crate::error::{CredentialFault, Member, RegistrationError};
use crate::ids::{CredentialIndex, DefinitionIndex, IconIndex};
use crate::registration::{
    Diagnostics, Icon, RegisteredCard, RegisteredCredential, RegisteredType, Registration, Version,
};
use crate::wire::{self, Map};

/// The members of a registration.
const MEMBERS: [Member; 10] = [
    Member::Version,
    Member::RegisteredAt,
    Member::Language,
    Member::Diagnostics,
    Member::Systems,
    Member::VerifierId,
    Member::Icons,
    Member::DefaultIcon,
    Member::Definitions,
    Member::Credentials,
];

/// The members of a registered credential.
const CREDENTIAL_MEMBERS: [Member; 10] = [
    Member::Entry,
    Member::Format,
    Member::Type,
    Member::Key,
    Member::Claims,
    Member::Card,
    Member::Labels,
    Member::Background,
    Member::Trust,
    Member::Transactions,
];

impl Registration {
    /// The registration of `bytes`: a CBOR map of [`Version::CURRENT`], the time its facts hold at, the
    /// wallet's language, the diagnostics, the nym_auth systems, the icon table, the table of
    /// projected definitions, each in the wallet's language, and the credentials, each
    /// `credentialId` and each batch once.
    ///
    /// # Errors
    ///
    /// [`RegistrationError`]: the first rule `bytes` break, the version first.
    pub fn read(bytes: &[u8]) -> Result<Self, RegistrationError> {
        let item = cbor::decode(bytes).map_err(RegistrationError::Cbor)?;
        let fields = Map::of(&item).map_err(|_| RegistrationError::NotMap)?;
        let version = Version::of(fields.read(Member::Version, wire::unsigned)?)
            .map_err(RegistrationError::Version)?;
        if let Some(unknown) = fields.unknown(&MEMBERS) {
            return Err(RegistrationError::MemberUnknown(unknown));
        }
        let registered_at = fields
            .require(Member::RegisteredAt)?
            .untag(0)
            .and_then(Item::as_text)
            .and_then(DateTime::parse)
            .ok_or(RegistrationError::RegisteredAt)?;
        let language = fields.read(Member::Language, Item::as_text)?;
        let language = Locale::parse(language).map_err(RegistrationError::Language)?;
        let diagnostics = match fields.read(Member::Diagnostics, wire::boolean)? {
            true => Diagnostics::Shown,
            false => Diagnostics::Hidden,
        };
        let systems = fields
            .read(Member::Systems, Item::as_array)?
            .iter()
            .map(|system| {
                let id = system.as_text().ok_or(RegistrationError::Member(
                    Member::Systems,
                    MemberFault::WrongType,
                ))?;
                NymAuthSystem::from_id(&SystemId::new(id))
                    .ok_or_else(|| RegistrationError::System(id.to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let form = fields.read(Member::VerifierId, Item::as_text)?;
        let verifier_id = wire::verifier_id_form(form)
            .ok_or_else(|| RegistrationError::VerifierIdForm(form.to_owned()))?;
        let icons = fields
            .read(Member::Icons, Item::as_array)?
            .iter()
            .enumerate()
            .map(|(at, icon)| {
                let bytes = icon.as_bytes().ok_or(RegistrationError::Member(
                    Member::Icons,
                    MemberFault::Entry(ArrayIndex::new(at)),
                ))?;
                Icon::new(bytes.to_vec())
                    .map_err(|_| RegistrationError::IconEmpty(IconIndex::new(at)))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let at = fields.read(Member::DefaultIcon, wire::position)?;
        let default_icon = icons
            .get(at)
            .ok_or(RegistrationError::DefaultIconUnknown(IconIndex::new(at)))?
            .clone();
        let definitions = fields
            .read(Member::Definitions, Item::as_array)?
            .iter()
            .enumerate()
            .map(|(at, definition)| definition_at(DefinitionIndex::new(at), definition, &language))
            .collect::<Result<Vec<_>, _>>()?;
        let table = Tables {
            icons: &icons,
            definitions: &definitions,
        };
        let credentials = fields
            .read(Member::Credentials, Item::as_array)?
            .iter()
            .enumerate()
            .map(|(at, credential)| {
                table
                    .credential(credential)
                    .map_err(|fault| RegistrationError::Credential(CredentialIndex::new(at), fault))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(at) = repeated_entry(&credentials) {
            return Err(RegistrationError::EntryRepeated(CredentialIndex::new(at)));
        }
        Ok(Self {
            version,
            registered_at,
            language,
            diagnostics,
            systems,
            verifier_id,
            default_icon,
            credentials,
        })
    }
}

/// The definition at `at`, the text of a projection in `language`.
fn definition_at(
    at: DefinitionIndex,
    item: &Item<'_>,
    language: &Locale,
) -> Result<Projected, RegistrationError> {
    let text = item.as_text().ok_or(RegistrationError::Member(
        Member::Definitions,
        MemberFault::Entry(ArrayIndex::new(at.value())),
    ))?;
    let projected =
        Projected::parse(text).map_err(|error| RegistrationError::Definition(at, error))?;
    if projected.language() != language {
        return Err(RegistrationError::DefinitionLanguage(at));
    }
    Ok(projected)
}

/// The position of the first credential whose `credentialId` or batch an earlier one has.
fn repeated_entry(credentials: &[RegisteredCredential]) -> Option<usize> {
    credentials.iter().enumerate().find_map(|(at, credential)| {
        let entry = credential.entry;
        credentials
            .iter()
            .take(at)
            .any(|earlier| {
                earlier.entry.credential_id() == entry.credential_id()
                    || earlier.entry.batch_id() == entry.batch_id()
            })
            .then_some(at)
    })
}

/// The tables a credential refers to.
struct Tables<'t> {
    icons: &'t [Icon],
    definitions: &'t [Projected],
}

impl Tables<'_> {
    /// The credential of `item`.
    fn credential(&self, item: &Item<'_>) -> Result<RegisteredCredential, CredentialFault> {
        let fields = Map::of(item).map_err(|_| CredentialFault::NotMap)?;
        if let Some(unknown) = fields.unknown(&CREDENTIAL_MEMBERS) {
            return Err(CredentialFault::MemberUnknown(unknown));
        }
        let entry = fields.read(Member::Entry, wire::entry)?;
        let format = fields.read(Member::Format, Item::as_text)?;
        let name = fields.read(Member::Type, Item::as_text)?;
        if name.is_empty() {
            return Err(CredentialFault::TypeEmpty);
        }
        let format = [Format::SdJwtVc, Format::Mdoc]
            .into_iter()
            .find(|known| known.identifier() == format)
            .ok_or_else(|| CredentialFault::Format(format.to_owned()))?;
        let credential_type = match format {
            Format::SdJwtVc => RegisteredType::Vct(Vct::new(name)),
            Format::Mdoc => RegisteredType::DocType(DocType::new(name)),
        };
        let key = match fields.read(Member::Key, wire::boolean)? {
            true => KeyHolding::Held,
            false => KeyHolding::NotHeld,
        };
        let claims = ClaimTree::from_cbor(format, fields.require(Member::Claims)?)
            .map_err(CredentialFault::Claims)?;
        let presentability = match fields.read(Member::Background, wire::boolean)? {
            true => Presentability::WithoutUi,
            false => Presentability::OnWalletUi,
        };
        Ok(RegisteredCredential {
            entry,
            credential_type,
            key,
            claims,
            card: self.card(fields.require(Member::Card)?)?,
            labels: labels(fields.require(Member::Labels)?)?,
            presentability,
            issuer: facts(fields.require(Member::Trust)?)?,
            transactions: self.transactions(fields.require(Member::Transactions)?)?,
        })
    }

    /// The card of `item`: its title, its issuer line, and the position of its icon.
    fn card(&self, item: &Item<'_>) -> Result<RegisteredCard, CredentialFault> {
        let fields = Map::of(item).map_err(|fault| CredentialFault::Member(Member::Card, fault))?;
        if let Some(unknown) = fields.unknown(&[Member::Title, Member::Issuer, Member::Icon]) {
            return Err(CredentialFault::MemberUnknown(unknown));
        }
        let text = |member: Member| {
            let text = fields
                .require(member)?
                .as_text()
                .ok_or(CredentialFault::Member(member, MemberFault::WrongType))?;
            CardText::new(text).map_err(CredentialFault::Text)
        };
        let at = wire::position(fields.require(Member::Icon)?).ok_or(CredentialFault::Member(
            Member::Icon,
            MemberFault::WrongType,
        ))?;
        let icon = self
            .icons
            .get(at)
            .ok_or(CredentialFault::IconUnknown(IconIndex::new(at)))?;
        Ok(RegisteredCard {
            title: text(Member::Title)?,
            issuer: text(Member::Issuer)?,
            icon: icon.clone(),
        })
    }

    /// What `item` records the sources serve: `{served: [[type, definition or reason], …],
    /// otherwise: reason}`.
    fn transactions(&self, item: &Item<'_>) -> Result<ServedTypes<Projected>, CredentialFault> {
        let malformed = |member| CredentialFault::Member(member, MemberFault::WrongType);
        let fields =
            Map::of(item).map_err(|fault| CredentialFault::Member(Member::Transactions, fault))?;
        if let Some(unknown) = fields.unknown(&[Member::ServedTypes, Member::Otherwise]) {
            return Err(CredentialFault::MemberUnknown(unknown));
        }
        let served = fields
            .read(Member::ServedTypes, Item::as_array)?
            .iter()
            .map(|served| {
                let [type_id, served] = served.as_array().ok_or(malformed(Member::ServedTypes))?
                else {
                    return Err(malformed(Member::ServedTypes));
                };
                let type_id = type_id.as_text().ok_or(malformed(Member::ServedTypes))?;
                let type_id = TypeId::parse(type_id).map_err(CredentialFault::TypeId)?;
                let served = match wire::position(served) {
                    Some(at) => Ok(self.definition(DefinitionIndex::new(at))?),
                    None => Err(wire::unserved(served)?),
                };
                Ok((type_id, served))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let otherwise = wire::unserved(fields.require(Member::Otherwise)?)?;
        ServedTypes::new(served, otherwise).map_err(CredentialFault::TypeRepeated)
    }

    /// The definition at `at` of the table.
    fn definition(&self, at: DefinitionIndex) -> Result<Projected, CredentialFault> {
        self.definitions
            .get(at.value())
            .cloned()
            .ok_or(CredentialFault::DefinitionUnknown(at))
    }
}

/// The labels of `item`: `{types: […], configuration: […]}`, each description `[path, label]`
/// or `[path]`.
fn labels(item: &Item<'_>) -> Result<ClaimLabels, CredentialFault> {
    let fields = Map::of(item).map_err(|fault| CredentialFault::Member(Member::Labels, fault))?;
    if let Some(unknown) = fields.unknown(&[Member::TypeLabels, Member::IssuerLabels]) {
        return Err(CredentialFault::MemberUnknown(unknown));
    }
    let described = |member: Member| -> Result<Vec<DescribedLabel>, CredentialFault> {
        let malformed = CredentialFault::Member(member, MemberFault::WrongType);
        fields
            .read(member, Item::as_array)?
            .iter()
            .map(|description| {
                let (path, label) = match description.as_array().ok_or(malformed.clone())? {
                    [path] => (path, None),
                    [path, label] => (path, Some(label)),
                    _ => return Err(malformed.clone()),
                };
                let path = wire::path(path).map_err(CredentialFault::Path)?;
                let label = label
                    .map(|label| {
                        let text = label.as_text().ok_or(malformed.clone())?;
                        LabelText::new(text).map_err(CredentialFault::Text)
                    })
                    .transpose()?;
                Ok(DescribedLabel::new(path, label))
            })
            .collect()
    };
    Ok(ClaimLabels::new(
        described(Member::TypeLabels)?,
        described(Member::IssuerLabels)?,
    ))
}

/// The issuer facts of `item`: `{aki: [keyIdentifier, …], admitting: [[type, value], …]}`.
fn facts(item: &Item<'_>) -> Result<IssuerFacts, CredentialFault> {
    let fields = Map::of(item).map_err(|fault| CredentialFault::Member(Member::Trust, fault))?;
    if let Some(unknown) = fields.unknown(&[Member::KeyIdentifiers, Member::Admitting]) {
        return Err(CredentialFault::MemberUnknown(unknown));
    }
    let entries = |member: Member| fields.read(member, Item::as_array);
    let key_identifiers = entries(Member::KeyIdentifiers)?
        .iter()
        .map(|key| {
            let bytes = key.as_bytes().ok_or(CredentialFault::Member(
                Member::KeyIdentifiers,
                MemberFault::WrongType,
            ))?;
            KeyIdentifier::new(bytes).map_err(CredentialFault::KeyIdentifier)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let admitting = entries(Member::Admitting)?
        .iter()
        .map(wire::authority)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(IssuerFacts::new(key_identifiers, admitting))
}
