//! The wallet's writing of a registration (K1, TR5).

use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_credential::{least_used, ClaimTree, Credential, TreeError, UsableCredential};
use siros_display::{CardFallback, DescribedLabel, DisplayCache, Locale};
use siros_presentation::{KeyHolding, MatchCredential};
use siros_transaction_data::{Configuration, HeldMetadata, Projected, ServedTypes, SourceInputs};
use siros_trust::{IssuerFacts, TrustStore};
use siros_wallet_state::{CredentialId, PresentationRecord};
use siros_zkp_req_nym_auth::catalogue::{ATTESTATION_TYPES, UNDISCLOSABLE};
use siros_zkp_req_nym_auth::system::NymAuthSystem;

use crate::error::Member;
use crate::icon::RasterIcon;
use crate::registration::{Diagnostics, Icon, Version};
use crate::wire::write::{self as wire, map};

/// What a registration is made from: the wallet state, the metadata the host holds, the trust
/// store and the time.
#[derive(Clone, Copy)]
pub struct RegistrationInput<'a> {
    /// The wallet's credentials. The registration holds those usable at `now` (C4), one instance
    /// per batch: the one the wallet presents next (C5).
    pub credentials: &'a [Credential],
    /// The wallet's presentation records, which choose the instance of each batch (C5).
    pub records: &'a [PresentationRecord],
    /// The display metadata the host holds.
    pub display: &'a DisplayCache,
    /// The wallet's language, which every card, label and definition is projected to (D2).
    pub language: &'a Locale,
    /// The title and issuer line the host shows, in the wallet's language, for a credential
    /// whose display metadata names none.
    pub card_fallback: &'a CardFallback,
    /// The transaction metadata the host holds.
    pub held: &'a HeldMetadata,
    /// The transaction data types the host configures.
    pub configuration: &'a Configuration,
    /// The trust store the host provisions, which the issuer facts are resolved against (TR5).
    pub trust: &'a TrustStore,
    /// The nym_auth systems whose circuits the host loaded, in the wallet's order of
    /// preference.
    pub systems: &'a [NymAuthSystem],
    /// The credentials the wallet declares presentable without its UI (A9).
    pub background: &'a [CredentialId],
    /// The icon the host prepared for each credential whose display metadata gives one: its
    /// background image, else its issuer's logo, rasterised and resized by the host.
    pub icons: &'a [CredentialIcon],
    /// The wallet's icon, for every credential without one of its own: Credential Manager drops
    /// an entry without an icon.
    pub default_icon: &'a RasterIcon,
    /// Whether the picker names why a request has no offer.
    pub diagnostics: Diagnostics,
    /// The time the registration's facts hold at.
    pub now: DateTime,
}

/// The icon the host prepared for a credential's card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialIcon {
    /// The credential.
    pub credential: CredentialId,
    /// The icon.
    pub icon: RasterIcon,
}

/// Why the wallet's state gives no registration.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{}", self.code())]
pub enum WriteError {
    /// The claims of this credential make no claim tree.
    Claims(CredentialId, #[source] TreeError),
}

impl WriteError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Claims(_, error) => error.code(),
        }
    }
}

/// The tables a registration's credentials refer to, filled as the credentials are written.
#[derive(Default)]
struct Tables {
    icons: Vec<Icon>,
    definitions: Vec<Projected>,
}

impl Tables {
    /// The position of `icon` in the icon table, added when it is new.
    fn icon(&mut self, icon: &Icon) -> u64 {
        position_of(&mut self.icons, icon)
    }

    /// The position of `definition` in the definition table, added when it is new.
    fn definition(&mut self, definition: Projected) -> u64 {
        position_of(&mut self.definitions, &definition)
    }
}

/// The position of `item` in `table`, added at the end when the table lacks it.
fn position_of<T: PartialEq + Clone>(table: &mut Vec<T>, item: &T) -> u64 {
    let at = match table.iter().position(|held| held == item) {
        Some(at) => at,
        None => {
            table.push(item.clone());
            table.len() - 1
        }
    };
    // A table holds fewer items than memory has bytes.
    at as u64
}

/// The registration of `input`: its credentials usable at `now`, one instance per batch, each
/// with its entry, type, holder-key presence, claim tree (a nym_auth attestation's without its
/// undisclosable attributes, R-G6), card and claim labels in the wallet's language,
/// presentability without the UI, issuer facts at `now` (TR5), and the transaction data
/// definitions its sources serve, projected (T3), each distinct definition stored once.
///
/// # Errors
///
/// [`WriteError::Claims`]: a claim tree out of CBOR's integers.
pub fn write(input: &RegistrationInput<'_>) -> Result<Vec<u8>, WriteError> {
    let usable: Vec<UsableCredential<'_>> = input
        .credentials
        .iter()
        .filter_map(|credential| UsableCredential::at(credential, input.now).ok())
        .collect();
    let sources = SourceInputs {
        trust: input.trust,
        held: input.held,
        display: input.display,
        configuration: input.configuration,
        language: input.language,
        now: input.now,
    };
    let mut tables = Tables::default();
    let default_icon = tables.icon(input.default_icon.icon());
    let credentials = least_used(&usable, input.records)
        .into_iter()
        .map(|usable| credential(input, &sources, &mut tables, usable))
        .collect::<Result<Vec<_>, _>>()?;
    let registration = map([
        (Member::Version, Cbor::Unsigned(Version::CURRENT.number())),
        (
            Member::RegisteredAt,
            Cbor::Tag(0, Box::new(Cbor::Text(input.now.to_string()))),
        ),
        (Member::Language, Cbor::text(input.language.as_str())),
        (
            Member::Diagnostics,
            Cbor::Bool(input.diagnostics == Diagnostics::Shown),
        ),
        (
            Member::Systems,
            Cbor::Array(
                input
                    .systems
                    .iter()
                    .map(|system| Cbor::text(system.id().as_str()))
                    .collect(),
            ),
        ),
        (
            Member::Icons,
            Cbor::Array(
                tables
                    .icons
                    .iter()
                    .map(|icon| Cbor::Bytes(icon.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (Member::DefaultIcon, Cbor::Unsigned(default_icon)),
        (
            Member::Definitions,
            Cbor::Array(
                tables
                    .definitions
                    .iter()
                    .map(|definition| Cbor::Text(definition.to_json()))
                    .collect(),
            ),
        ),
        (Member::Credentials, Cbor::Array(credentials)),
    ]);
    Ok(registration.encode())
}

/// The registered form of `usable`.
fn credential(
    input: &RegistrationInput<'_>,
    sources: &SourceInputs<'_>,
    tables: &mut Tables,
    usable: &UsableCredential<'_>,
) -> Result<Cbor, WriteError> {
    let credential = usable.credential();
    let id = credential.entry().credential_id();
    let credential_type = credential.credential_type();
    let mut claims = ClaimTree::of(credential).map_err(|error| WriteError::Claims(id, error))?;
    if ATTESTATION_TYPES.contains(&credential_type.as_str()) {
        claims = claims.without(&UNDISCLOSABLE);
    }
    let labels = input.display.claim_labels(credential, input.language);
    Ok(map([
        (Member::Entry, wire::entry(credential.entry())),
        (Member::Format, Cbor::text(credential.format().identifier())),
        (Member::Type, Cbor::text(credential_type.as_str())),
        (
            Member::Key,
            Cbor::Bool(usable.key_holding() == KeyHolding::Held),
        ),
        (Member::Claims, claims.to_cbor()),
        (Member::Card, card(input, tables, credential)),
        (
            Member::Labels,
            map([
                (Member::TypeLabels, described(labels.types())),
                (Member::IssuerLabels, described(labels.issuer())),
            ]),
        ),
        (
            Member::Background,
            Cbor::Bool(input.background.contains(&id)),
        ),
        (Member::Trust, trust(input, credential)),
        (
            Member::Transactions,
            transactions(tables, &sources.served_types(credential)),
        ),
    ]))
}

/// The card of `credential` in the wallet's language: its title, its issuer line, and the
/// position of its icon: the one the host prepared for it, else the wallet's.
fn card(input: &RegistrationInput<'_>, tables: &mut Tables, credential: &Credential) -> Cbor {
    let id = credential.entry().credential_id();
    let card = input
        .display
        .card(credential, input.language, input.card_fallback);
    let icon = input
        .icons
        .iter()
        .find(|icon| icon.credential == id)
        .map_or(input.default_icon, |icon| &icon.icon);
    map([
        (Member::Title, Cbor::text(card.title().as_str())),
        (Member::Issuer, Cbor::text(card.issuer().as_str())),
        (Member::Icon, Cbor::Unsigned(tables.icon(icon.icon()))),
    ])
}

/// The descriptions `descriptions`, each `[path, label]`, or `[path]` without a label in the
/// wallet's language.
fn described(descriptions: &[DescribedLabel]) -> Cbor {
    Cbor::Array(
        descriptions
            .iter()
            .map(|description| {
                let path = wire::path(description.path());
                let label = description.label().map(|label| Cbor::text(label.as_str()));
                Cbor::Array(std::iter::once(path).chain(label).collect())
            })
            .collect(),
    )
}

/// The issuer facts of `credential` at the registration's time (TR5).
fn trust(input: &RegistrationInput<'_>, credential: &Credential) -> Cbor {
    let facts = IssuerFacts::at(credential.issuer_chain(), input.trust, input.now);
    map([
        (
            Member::KeyIdentifiers,
            Cbor::Array(
                facts
                    .key_identifiers()
                    .iter()
                    .map(|key| Cbor::Bytes(key.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            Member::Admitting,
            Cbor::Array(facts.admitting().iter().map(wire::authority).collect()),
        ),
    ])
}

/// What `served`, the record of a credential's sources, gives each type: the position of the
/// projected definition in the table, or why there is none.
fn transactions(tables: &mut Tables, served: &ServedTypes<Projected>) -> Cbor {
    let types = served
        .types()
        .iter()
        .map(|(type_id, served)| {
            let served = match served {
                Ok(definition) => Cbor::Unsigned(tables.definition(definition.clone())),
                Err(unserved) => wire::unserved(*unserved),
            };
            Cbor::Array(vec![Cbor::text(type_id.as_str()), served])
        })
        .collect();
    map([
        (Member::ServedTypes, Cbor::Array(types)),
        (Member::Otherwise, wire::unserved(served.otherwise())),
    ])
}
