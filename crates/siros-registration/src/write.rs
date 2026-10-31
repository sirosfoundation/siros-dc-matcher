//! The wallet's projection of its state to a registration (K1, TR5).

use siros_codec::date::DateTime;
use siros_credential::{least_used, ClaimTree, Credential, TreeError, UsableCredential};
use siros_display::{CardWording, DisplayCache, Locale};
use siros_presentation::{MatchCredential, Presentability};
use siros_transaction_data::{Configuration, HeldMetadata, Projected, SourceInputs};
use siros_trust::{IssuerFacts, TrustStore};
use siros_wallet_state::{CredentialId, PresentationRecord};
use siros_zkp_req_nym_auth::catalogue::{ATTESTATION_TYPES, UNDISCLOSABLE};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;

use crate::encode::encode;
use crate::icon::RasterIcon;
use crate::layout::SectionKind;
use crate::registration::{
    Diagnostics, Facts, Icon, Projection, RegisteredCard, RegisteredCredential, RegisteredType,
    TypeName,
};

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
    /// The texts the host gives cards in the wallet's language: the title and issuer line of a
    /// credential whose display metadata names none, and the template of a named issuer's line.
    pub card_wording: &'a CardWording,
    /// The transaction metadata the host holds.
    pub held: &'a HeldMetadata,
    /// The transaction data types the host configures.
    pub configuration: &'a Configuration,
    /// The trust store the host provisions, which the issuer facts are resolved against (TR5).
    pub trust: &'a TrustStore,
    /// The nym_auth systems whose circuits the host loaded, in the wallet's order of
    /// preference.
    pub systems: &'a [NymAuthSystem],
    /// The form of the nym_auth `verifier_id` the wallet's trust framework fixes, which the
    /// picker applies as the wallet's plan does.
    pub verifier_id: VerifierIdForm,
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
    /// This credential's `vct` or `docType` is the empty string.
    TypeEmpty(CredentialId),
    /// This section, or the sections up to its end, holds more bytes than a 32-bit offset
    /// reaches, or than a buffer of the platform holds (`isize::MAX`).
    TooLarge(SectionKind),
}

impl WriteError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Claims(_, error) => error.code(),
            Self::TypeEmpty(_) => "registration_credential_type_empty",
            Self::TooLarge(_) => "registration_too_large",
        }
    }
}

/// The registration of `input`, as [`encode`] lays [`project`]'s projection out.
///
/// # Errors
///
/// [`WriteError`]: a claim tree out of CBOR's integers, an empty `vct` or `docType`, or a
/// registration past 4 GiB or past the longest buffer of the platform.
pub fn write(input: &RegistrationInput<'_>) -> Result<Vec<u8>, WriteError> {
    encode(&project(input)?)
}

/// The projection of `input`: its credentials usable at `now`, one instance per batch, each
/// with its entry, type, holder-key presence, claim tree (a nym_auth attestation's without its
/// undisclosable attributes, R-G6), card and claim labels in the wallet's language,
/// presentability without the UI, issuer facts at `now` (TR5), and the transaction data
/// definitions its sources serve, projected (T3).
///
/// # Errors
///
/// [`WriteError::Claims`]: a claim tree out of CBOR's integers; [`WriteError::TypeEmpty`]: an
/// empty `vct` or `docType`.
pub fn project(input: &RegistrationInput<'_>) -> Result<Projection, WriteError> {
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
    let credentials = least_used(&usable, input.records)
        .into_iter()
        .map(|usable| credential(input, &sources, usable))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Projection {
        facts: Facts {
            registered_at: input.now,
            language: input.language.clone(),
            diagnostics: input.diagnostics,
            systems: input.systems.to_vec(),
            verifier_id: input.verifier_id,
            default_icon: input.default_icon.icon().clone(),
        },
        credentials,
    })
}

/// The registered form of `usable`.
fn credential(
    input: &RegistrationInput<'_>,
    sources: &SourceInputs<'_>,
    usable: &UsableCredential<'_>,
) -> Result<RegisteredCredential<Projected, Icon>, WriteError> {
    let credential = usable.credential();
    let id = credential.entry().credential_id();
    let credential_type = credential.credential_type();
    let mut claims = ClaimTree::of(credential).map_err(|error| WriteError::Claims(id, error))?;
    if ATTESTATION_TYPES.contains(&credential_type.as_str()) {
        claims = claims.without(&UNDISCLOSABLE);
    }
    let presentability = if input.background.contains(&id) {
        Presentability::WithoutUi
    } else {
        Presentability::OnWalletUi
    };
    Ok(RegisteredCredential {
        entry: credential.entry(),
        credential_type: RegisteredType::new(
            credential.format(),
            TypeName::new(credential_type.as_str()).map_err(|_| WriteError::TypeEmpty(id))?,
        ),
        key: usable.key_holding(),
        claims,
        card: card(input, credential),
        labels: input.display.claim_labels(credential, input.language),
        presentability,
        issuer: IssuerFacts::at(credential.issuer_chain(), input.trust, input.now),
        transactions: sources.served_types(credential),
    })
}

/// The card of `credential` in the wallet's language: its title, its issuer line, and the icon
/// the host prepared for it, else the wallet's.
fn card(input: &RegistrationInput<'_>, credential: &Credential) -> RegisteredCard<Icon> {
    let id = credential.entry().credential_id();
    let card = input
        .display
        .card(credential, input.language, input.card_wording);
    let icon = input
        .icons
        .iter()
        .find(|icon| icon.credential == id)
        .map_or(input.default_icon, |icon| &icon.icon);
    RegisteredCard {
        title: card.title().clone(),
        issuer: card.issuer().clone(),
        icon: icon.icon().clone(),
    }
}
