//! The reading of a registration's facts and credential records from their CBOR, as the wallet
//! writes them.

use siros_codec::cbor::Item;
use siros_codec::date::DateTime;
use siros_codec::member::MemberFault;
use siros_credential::ClaimTree;
use siros_display::{CardText, ClaimLabels, DescribedLabel, LabelText, Locale};
use siros_presentation::{KeyHolding, Presentability};
use siros_transaction_data::{ServedTypes, TypeId};
use siros_trust::{IssuerFacts, KeyIdentifier};
use siros_zkp_req::SystemId;
use siros_zkp_req_nym_auth::system::NymAuthSystem;

use crate::error::{CredentialFault, FactsFault, Member};
use crate::ids::CredentialIndex;
use crate::layout::{Bounds, Directory, IconsPart};
use crate::registration::{
    DefinitionRef, Diagnostics, Facts, IconRef, RegisteredCard, RegisteredCredential,
    RegisteredType,
};
use crate::wire::{self, Map};

/// The members of the facts.
const FACTS_MEMBERS: [Member; 6] = [
    Member::RegisteredAt,
    Member::Language,
    Member::Diagnostics,
    Member::Systems,
    Member::VerifierId,
    Member::DefaultIcon,
];

/// The members of a credential record.
const RECORD_MEMBERS: [Member; 9] = [
    Member::Position,
    Member::Entry,
    Member::Key,
    Member::Claims,
    Member::Card,
    Member::Labels,
    Member::Background,
    Member::Trust,
    Member::Transactions,
];

/// A credential record: the credential's position in the wallet's order, and the credential.
pub(crate) struct Positioned {
    pub(crate) position: CredentialIndex,
    pub(crate) credential: RegisteredCredential,
}

/// The facts of `item`: a map of the time the facts hold at, the wallet's language, the
/// diagnostics, the nym_auth systems, the `verifier_id` form, and the span of the wallet's icon
/// in `icons`.
pub(crate) fn facts(item: &Item<'_>, icons: &Bounds<IconsPart>) -> Result<Facts, FactsFault> {
    let fields = Map::of(item).map_err(|_| FactsFault::NotMap)?;
    if let Some(unknown) = fields.unknown(&FACTS_MEMBERS) {
        return Err(FactsFault::MemberUnknown(unknown));
    }
    let registered_at = fields
        .require(Member::RegisteredAt)?
        .untag(0)
        .and_then(Item::as_text)
        .and_then(DateTime::parse)
        .ok_or(FactsFault::RegisteredAt)?;
    let language = fields.read(Member::Language, Item::as_text)?;
    let language = Locale::parse(language).map_err(FactsFault::Language)?;
    let diagnostics = match fields.read(Member::Diagnostics, wire::boolean)? {
        true => Diagnostics::Shown,
        false => Diagnostics::Hidden,
    };
    let systems = fields
        .read(Member::Systems, Item::as_array)?
        .iter()
        .map(|system| {
            let id = system
                .as_text()
                .ok_or(FactsFault::Member(Member::Systems, MemberFault::WrongType))?;
            NymAuthSystem::from_id(&SystemId::new(id))
                .ok_or_else(|| FactsFault::System(id.to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let form = fields.read(Member::VerifierId, Item::as_text)?;
    let verifier_id =
        wire::verifier_id_form(form).ok_or_else(|| FactsFault::VerifierIdForm(form.to_owned()))?;
    let icon = fields.read(Member::DefaultIcon, wire::span)?;
    let icon = icons
        .span(icon.offset, icon.length)
        .map_err(FactsFault::DefaultIcon)?;
    Ok(Facts {
        registered_at,
        language,
        diagnostics,
        systems,
        verifier_id,
        default_icon: IconRef::of(icon).map_err(|_| FactsFault::DefaultIconEmpty)?,
    })
}

/// The record of `item`, a credential of `credential_type`: a map of its position, entry,
/// holder-key presence, claims, card, labels, presentability, issuer facts and served types,
/// its spans in the sections of `directory`.
pub(crate) fn credential(
    item: &Item<'_>,
    credential_type: &RegisteredType,
    directory: &Directory,
) -> Result<Positioned, CredentialFault> {
    let fields = Map::of(item).map_err(|_| CredentialFault::NotMap)?;
    if let Some(unknown) = fields.unknown(&RECORD_MEMBERS) {
        return Err(CredentialFault::MemberUnknown(unknown));
    }
    let position = fields.read(Member::Position, wire::position)?;
    let entry = fields.read(Member::Entry, wire::entry)?;
    let key = match fields.read(Member::Key, wire::boolean)? {
        true => KeyHolding::Held,
        false => KeyHolding::NotHeld,
    };
    let claims = ClaimTree::from_cbor(credential_type.format(), fields.require(Member::Claims)?)
        .map_err(CredentialFault::Claims)?;
    let presentability = match fields.read(Member::Background, wire::boolean)? {
        true => Presentability::WithoutUi,
        false => Presentability::OnWalletUi,
    };
    let credential = RegisteredCredential {
        entry,
        credential_type: credential_type.clone(),
        key,
        claims,
        card: card(fields.require(Member::Card)?, &directory.icons)?,
        labels: labels(fields.require(Member::Labels)?)?,
        presentability,
        issuer: facts_of_issuer(fields.require(Member::Trust)?)?,
        transactions: transactions(fields.require(Member::Transactions)?, directory)?,
    };
    Ok(Positioned {
        position: CredentialIndex::new(position),
        credential,
    })
}

/// The card of `item`: its title, its issuer line, and the span of its icon in `icons`.
fn card(item: &Item<'_>, icons: &Bounds<IconsPart>) -> Result<RegisteredCard, CredentialFault> {
    let fields = Map::of(item).map_err(|fault| CredentialFault::Member(Member::Card, fault))?;
    if let Some(unknown) = fields.unknown(&[Member::Title, Member::Issuer, Member::Icon]) {
        return Err(CredentialFault::MemberUnknown(unknown));
    }
    let text = |member: Member| {
        let text = fields.read(member, Item::as_text)?;
        CardText::new(text).map_err(CredentialFault::Text)
    };
    let icon = fields.read(Member::Icon, wire::span)?;
    let icon = icons
        .span(icon.offset, icon.length)
        .map_err(|error| CredentialFault::Span(Member::Icon, error))?;
    Ok(RegisteredCard {
        title: text(Member::Title)?,
        issuer: text(Member::Issuer)?,
        icon: IconRef::of(icon).map_err(|_| CredentialFault::IconEmpty)?,
    })
}

/// What `item` records the sources serve: `{served: [[type, definition span or reason], …],
/// otherwise: reason}`, each span in the definitions section of `directory`.
fn transactions(
    item: &Item<'_>,
    directory: &Directory,
) -> Result<ServedTypes<DefinitionRef>, CredentialFault> {
    let malformed = || CredentialFault::Member(Member::ServedTypes, MemberFault::WrongType);
    let fields =
        Map::of(item).map_err(|fault| CredentialFault::Member(Member::Transactions, fault))?;
    if let Some(unknown) = fields.unknown(&[Member::ServedTypes, Member::Otherwise]) {
        return Err(CredentialFault::MemberUnknown(unknown));
    }
    let served = fields
        .read(Member::ServedTypes, Item::as_array)?
        .iter()
        .map(|served| {
            let [type_id, served] = served.as_array().ok_or_else(malformed)? else {
                return Err(malformed());
            };
            let type_id = type_id.as_text().ok_or_else(malformed)?;
            let type_id = TypeId::parse(type_id).map_err(CredentialFault::TypeId)?;
            let served = match wire::span(served) {
                Some(span) => Ok(directory
                    .definitions
                    .span(span.offset, span.length)
                    .map(DefinitionRef::of)
                    .map_err(|error| CredentialFault::Span(Member::ServedTypes, error))?),
                None => Err(wire::unserved(served)?),
            };
            Ok((type_id, served))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let otherwise = wire::unserved(fields.require(Member::Otherwise)?)?;
    ServedTypes::new(served, otherwise).map_err(CredentialFault::TypeRepeated)
}

/// The labels of `item`: `{types: […], configuration: […]}`, each description `[path, label]`
/// or `[path]`.
fn labels(item: &Item<'_>) -> Result<ClaimLabels, CredentialFault> {
    let fields = Map::of(item).map_err(|fault| CredentialFault::Member(Member::Labels, fault))?;
    if let Some(unknown) = fields.unknown(&[Member::TypeLabels, Member::IssuerLabels]) {
        return Err(CredentialFault::MemberUnknown(unknown));
    }
    let described = |member: Member| -> Result<Vec<DescribedLabel>, CredentialFault> {
        let malformed = || CredentialFault::Member(member, MemberFault::WrongType);
        fields
            .read(member, Item::as_array)?
            .iter()
            .map(|description| {
                let (path, label) = match description.as_array().ok_or_else(malformed)? {
                    [path] => (path, None),
                    [path, label] => (path, Some(label)),
                    _ => return Err(malformed()),
                };
                let path = wire::path(path).map_err(CredentialFault::Path)?;
                let label = label
                    .map(|label| {
                        let text = label.as_text().ok_or_else(malformed)?;
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
fn facts_of_issuer(item: &Item<'_>) -> Result<IssuerFacts, CredentialFault> {
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
