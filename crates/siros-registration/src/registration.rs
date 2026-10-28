//! A registration's contents (K1): its facts, and its credentials as the picker matches and
//! shows them.

use std::cmp::Ordering;

use serde_json::Value;
use siros_codec::date::DateTime;
use siros_credential::{ClaimTree, EntryRef, Format, Instance, TypedValue};
use siros_dcql::{ClaimPath, DocType, PathError, Vct};
use siros_display::{CardText, ClaimLabels, Locale};
use siros_presentation::{AskedType, KeyHolding, MatchCredential, Presentability};
use siros_transaction_data::{Definitions, Entry, Incompatibility, Projected, ServedTypes, TypeId};
use siros_trust::{Admission, FactRefusal, IssuerFacts, QueryAuthorities, Unadmitted};
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;

use crate::layout::{format_code, DefinitionsPart, IconsPart, Span};

/// The format version of a registration: the one this crate reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version(u32);

impl Version {
    /// The version this crate reads and writes.
    pub const CURRENT: Self = Self(1);

    /// The version `number`.
    ///
    /// # Errors
    ///
    /// `number`, back, for a version other than [`Version::CURRENT`].
    pub fn of(number: u32) -> Result<Self, u32> {
        if number == Self::CURRENT.0 {
            Ok(Self::CURRENT)
        } else {
            Err(number)
        }
    }

    /// The number.
    #[must_use]
    pub fn number(self) -> u32 {
        self.0
    }
}

/// Whether the picker shows an entry that names why a request has no offer. The wallet asks
/// for it in its debuggable builds only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Diagnostics {
    /// One entry names why a request has no offer.
    Shown,
    /// A request without an offer shows nothing.
    Hidden,
}

/// The image of a picker entry, as the wallet registered it: at least one byte. The wallet's
/// writer admits a raster icon of 64 to 256 pixels alone; the picker passes the bytes on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Icon(Vec<u8>);

/// Why bytes are no icon: there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("registration_icon_empty")]
pub struct IconEmpty;

impl Icon {
    /// The image `bytes`.
    ///
    /// # Errors
    ///
    /// [`IconEmpty`] for no byte: the host drops an entry without an image.
    pub fn new(bytes: Vec<u8>) -> Result<Self, IconEmpty> {
        if bytes.is_empty() {
            return Err(IconEmpty);
        }
        Ok(Self(bytes))
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The icon of `bytes`, which a raster icon or an [`IconRef`]'s span gives: at least one.
    pub(crate) fn of_held(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Where an icon lies in the registration's icons section: at least one byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IconRef(Span<IconsPart>);

impl IconRef {
    /// The icon of `span`.
    ///
    /// # Errors
    ///
    /// [`IconEmpty`] for a span of no byte.
    pub(crate) fn of(span: Span<IconsPart>) -> Result<Self, IconEmpty> {
        if span.length() == 0 {
            return Err(IconEmpty);
        }
        Ok(Self(span))
    }

    pub(crate) fn span(self) -> Span<IconsPart> {
        self.0
    }
}

/// Where a projected definition lies in the registration's definitions section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefinitionRef(Span<DefinitionsPart>);

impl DefinitionRef {
    pub(crate) fn of(span: Span<DefinitionsPart>) -> Self {
        Self(span)
    }

    pub(crate) fn span(self) -> Span<DefinitionsPart> {
        self.0
    }
}

/// What every request reads of a registration: the time its facts hold at, the wallet's
/// language, the diagnostics, the nym_auth systems, the `verifier_id` form, and the wallet's
/// icon, as `I`: an [`IconRef`] as the registration holds it, an [`Icon`] read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts<I = IconRef> {
    pub(crate) registered_at: DateTime,
    pub(crate) language: Locale,
    pub(crate) diagnostics: Diagnostics,
    pub(crate) systems: Vec<NymAuthSystem>,
    pub(crate) verifier_id: VerifierIdForm,
    pub(crate) default_icon: I,
}

impl<I> Facts<I> {
    /// The time the registration's facts hold at: the credentials' validity, their issuers'
    /// admission, and the dates of transaction data and `zkp_req` options.
    pub fn registered_at(&self) -> DateTime {
        self.registered_at
    }

    /// The wallet's language, which every card, label and definition is in.
    pub fn language(&self) -> &Locale {
        &self.language
    }

    /// Whether the picker names why a request has no offer.
    pub fn diagnostics(&self) -> Diagnostics {
        self.diagnostics
    }

    /// The nym_auth systems whose circuits the wallet loaded, in its order of preference.
    pub fn systems(&self) -> &[NymAuthSystem] {
        &self.systems
    }

    /// The form of the nym_auth `verifier_id` the wallet's trust framework fixes.
    pub fn verifier_id(&self) -> VerifierIdForm {
        self.verifier_id
    }

    /// The wallet's icon, which a picker entry without a credential shows.
    pub fn default_icon(&self) -> &I {
        &self.default_icon
    }

    /// The facts with the wallet's icon replaced by what `f` gives for it.
    ///
    /// # Errors
    ///
    /// The error of `f`.
    pub fn try_map_icon<J, X>(self, f: impl FnOnce(I) -> Result<J, X>) -> Result<Facts<J>, X> {
        Ok(Facts {
            registered_at: self.registered_at,
            language: self.language,
            diagnostics: self.diagnostics,
            systems: self.systems,
            verifier_id: self.verifier_id,
            default_icon: f(self.default_icon)?,
        })
    }
}

/// A credential's type, with the format it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegisteredType {
    /// An SD-JWT VC's `vct`.
    Vct(Vct),
    /// An mdoc's `docType`.
    DocType(DocType),
}

impl RegisteredType {
    /// The type `name` of `format`.
    pub fn new(format: Format, name: &str) -> Self {
        match format {
            Format::SdJwtVc => Self::Vct(Vct::new(name)),
            Format::Mdoc => Self::DocType(DocType::new(name)),
        }
    }

    /// The format the type belongs to.
    pub fn format(&self) -> Format {
        match self {
            Self::Vct(_) => Format::SdJwtVc,
            Self::DocType(_) => Format::Mdoc,
        }
    }

    /// The type's text.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Vct(vct) => vct.as_str(),
            Self::DocType(doc_type) => doc_type.as_str(),
        }
    }

    /// What the index sorts by: the format's code, then the name's bytes.
    fn sort_key(&self) -> (u32, &[u8]) {
        (format_code(self.format()), self.as_str().as_bytes())
    }
}

/// The index's order: by format code, then by the bytes of the name.
impl Ord for RegisteredType {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}

impl PartialOrd for RegisteredType {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<&AskedType> for RegisteredType {
    fn from(asked: &AskedType) -> Self {
        Self::new(asked.format(), asked.name())
    }
}

/// The type a Credential Query asks for is this type: the same format and name.
impl PartialEq<AskedType> for RegisteredType {
    fn eq(&self, asked: &AskedType) -> bool {
        self.format() == asked.format() && self.as_str() == asked.name()
    }
}

/// A credential as the picker matches and shows it. `D` is how it holds the definitions its
/// sources serve, `I` how it holds its card's icon: a [`DefinitionRef`] and an [`IconRef`] as
/// the registration holds them, a [`Projected`] and an [`Icon`] read.
#[derive(Debug, PartialEq)]
pub struct RegisteredCredential<D = DefinitionRef, I = IconRef> {
    pub(crate) entry: EntryRef,
    pub(crate) credential_type: RegisteredType,
    pub(crate) key: KeyHolding,
    pub(crate) claims: ClaimTree,
    pub(crate) card: RegisteredCard<I>,
    pub(crate) labels: ClaimLabels,
    pub(crate) presentability: Presentability,
    pub(crate) issuer: IssuerFacts,
    pub(crate) transactions: ServedTypes<D>,
}

/// What shows a credential in the picker: its title and issuer line in the wallet's language,
/// and its icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCard<I = IconRef> {
    pub(crate) title: CardText,
    pub(crate) issuer: CardText,
    pub(crate) icon: I,
}

impl<D, I> RegisteredCredential<D, I> {
    /// The entry the wallet presents: `credentialId`, batch and instance.
    pub fn entry(&self) -> EntryRef {
        self.entry
    }

    /// The type, with its format.
    pub fn credential_type(&self) -> &RegisteredType {
        &self.credential_type
    }

    /// The claims.
    pub fn claims(&self) -> &ClaimTree {
        &self.claims
    }

    /// The card.
    pub fn card(&self) -> &RegisteredCard<I> {
        &self.card
    }

    /// The claim labels in the wallet's language.
    pub fn labels(&self) -> &ClaimLabels {
        &self.labels
    }

    /// Whether the wallet presents the credential from its background service (A9).
    pub fn presentability(&self) -> Presentability {
        self.presentability
    }

    /// The issuer facts (TR5).
    pub fn issuer(&self) -> &IssuerFacts {
        &self.issuer
    }

    /// What the credential's sources serve for each transaction data type.
    pub fn transactions(&self) -> &ServedTypes<D> {
        &self.transactions
    }

    /// The credential with what its sources serve for the types of `named` alone, each
    /// definition replaced by what `f` gives for it: the types a request's entries name for it.
    /// Every other type gets [`ServedTypes::otherwise`].
    ///
    /// # Errors
    ///
    /// The first error of `f`.
    pub fn select<E, X>(
        self,
        named: &[TypeId],
        f: impl FnMut(&D) -> Result<E, X>,
    ) -> Result<RegisteredCredential<E, I>, X> {
        self.map_transactions(|served| served.select(named, f))
    }

    /// The credential with each definition its sources serve replaced by what `f` gives for it.
    ///
    /// # Errors
    ///
    /// The first error of `f`.
    pub fn try_map_definitions<E, X>(
        self,
        f: impl FnMut(D) -> Result<E, X>,
    ) -> Result<RegisteredCredential<E, I>, X> {
        self.map_transactions(|served| served.try_map(f))
    }

    /// The credential with its card's icon replaced by what `f` gives for it.
    ///
    /// # Errors
    ///
    /// The error of `f`.
    pub fn try_map_icon<J, X>(
        self,
        f: impl FnOnce(I) -> Result<J, X>,
    ) -> Result<RegisteredCredential<D, J>, X> {
        Ok(RegisteredCredential {
            entry: self.entry,
            credential_type: self.credential_type,
            key: self.key,
            claims: self.claims,
            card: RegisteredCard {
                title: self.card.title,
                issuer: self.card.issuer,
                icon: f(self.card.icon)?,
            },
            labels: self.labels,
            presentability: self.presentability,
            issuer: self.issuer,
            transactions: self.transactions,
        })
    }

    fn map_transactions<E, X>(
        self,
        f: impl FnOnce(ServedTypes<D>) -> Result<ServedTypes<E>, X>,
    ) -> Result<RegisteredCredential<E, I>, X> {
        Ok(RegisteredCredential {
            entry: self.entry,
            credential_type: self.credential_type,
            key: self.key,
            claims: self.claims,
            card: self.card,
            labels: self.labels,
            presentability: self.presentability,
            issuer: self.issuer,
            transactions: f(self.transactions)?,
        })
    }
}

impl<I> RegisteredCard<I> {
    /// The title.
    pub fn title(&self) -> &CardText {
        &self.title
    }

    /// The issuer line.
    pub fn issuer(&self) -> &CardText {
        &self.issuer
    }

    /// The icon.
    pub fn icon(&self) -> &I {
        &self.icon
    }
}

impl<D, I> Instance for &RegisteredCredential<D, I> {
    fn entry(&self) -> EntryRef {
        self.entry
    }
}

/// A credential of the registration, matched with the issuer facts it carries (TR5).
impl<D, I> MatchCredential for &RegisteredCredential<D, I> {
    type Admission = Admission;
    type Unadmitted = Unadmitted<FactRefusal>;
    type Trust = ();

    /// The admission of the issuer by `authorities` from the facts the wallet recorded at
    /// registration.
    fn admission(
        &self,
        authorities: &QueryAuthorities,
        _: &(),
    ) -> Result<Admission, Unadmitted<FactRefusal>> {
        Admission::of(authorities, &self.issuer)
    }

    fn format(&self) -> Format {
        self.credential_type.format()
    }

    fn credential_type(&self) -> &str {
        self.credential_type.as_str()
    }

    fn key_holding(&self) -> KeyHolding {
        self.key
    }

    fn claim_values(&self, path: &ClaimPath) -> Result<Vec<Value>, PathError> {
        Ok(self
            .claims
            .claims(path)?
            .into_iter()
            .map(TypedValue::to_json)
            .collect())
    }
}

/// The definitions the credential's sources serve, read from the registration.
impl<I> Definitions for RegisteredCredential<Projected, I> {
    fn serve(&self, entry: &Entry) -> Result<Projected, Incompatibility> {
        self.transactions
            .serve(entry.type_id())
            .cloned()
            .map_err(Incompatibility::Registered)
    }
}

/// A registration read whole: its facts, and its credentials in the wallet's order, each with
/// its definitions and icon. The writer lays it out ([`crate::encode`], feature `wallet`).
#[derive(Debug, PartialEq)]
pub struct Projection {
    pub(crate) facts: Facts<Icon>,
    pub(crate) credentials: Vec<RegisteredCredential<Projected, Icon>>,
}

impl Projection {
    /// The facts.
    pub fn facts(&self) -> &Facts<Icon> {
        &self.facts
    }

    /// The credentials, in the wallet's order.
    pub fn credentials(&self) -> &[RegisteredCredential<Projected, Icon>] {
        &self.credentials
    }
}
