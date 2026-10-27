//! A registration: what the wallet registers for the credential picker (K1), as the picker
//! holds it.

use serde_json::Value;
use siros_codec::date::DateTime;
use siros_credential::{ClaimTree, EntryRef, Format, Instance, TypedValue};
use siros_dcql::{ClaimPath, DocType, PathError, Vct};
use siros_display::{CardText, ClaimLabels, Locale};
use siros_presentation::{KeyHolding, MatchCredential, Presentability};
use siros_transaction_data::{Definitions, Entry, Incompatibility, Projected, ServedTypes};
use siros_trust::{Admission, FactRefusal, IssuerFacts, QueryAuthorities, Unadmitted};
use siros_zkp_req_nym_auth::system::NymAuthSystem;

/// The format version of a registration: the one this crate reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version(u64);

impl Version {
    /// The version this crate reads and writes.
    pub const CURRENT: Self = Self(2);

    /// The version `number`.
    ///
    /// # Errors
    ///
    /// `number`, back, for a version other than [`Version::CURRENT`].
    pub fn of(number: u64) -> Result<Self, u64> {
        if number == Self::CURRENT.0 {
            Ok(Self::CURRENT)
        } else {
            Err(number)
        }
    }

    /// The number.
    #[must_use]
    pub fn number(self) -> u64 {
        self.0
    }
}

/// What the wallet registers for the credential picker: its usable credentials, one instance
/// per batch, with what the picker shows and admits of each, at the time its facts hold.
pub struct Registration {
    pub(crate) version: Version,
    pub(crate) registered_at: DateTime,
    pub(crate) language: Locale,
    pub(crate) diagnostics: Diagnostics,
    pub(crate) systems: Vec<NymAuthSystem>,
    pub(crate) default_icon: Icon,
    pub(crate) credentials: Vec<RegisteredCredential>,
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

/// A credential's type, with the format it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RegisteredType {
    /// An SD-JWT VC's `vct`.
    Vct(Vct),
    /// An mdoc's `docType`.
    DocType(DocType),
}

/// A credential as the picker matches and shows it.
pub struct RegisteredCredential {
    pub(crate) entry: EntryRef,
    pub(crate) credential_type: RegisteredType,
    pub(crate) key: KeyHolding,
    pub(crate) claims: ClaimTree,
    pub(crate) card: RegisteredCard,
    pub(crate) labels: ClaimLabels,
    pub(crate) presentability: Presentability,
    pub(crate) issuer: IssuerFacts,
    pub(crate) transactions: ServedTypes<Projected>,
}

/// What shows a credential in the picker: its title and issuer line in the wallet's language,
/// and its icon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCard {
    pub(crate) title: CardText,
    pub(crate) issuer: CardText,
    pub(crate) icon: Icon,
}

impl Registration {
    /// The format version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

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

    /// The wallet's icon, which a picker entry without a credential shows.
    pub fn default_icon(&self) -> &Icon {
        &self.default_icon
    }

    /// The credentials, in the wallet's order.
    pub fn credentials(&self) -> &[RegisteredCredential] {
        &self.credentials
    }
}

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

    /// The icon of a raster image the writer read, which has bytes.
    #[cfg(feature = "wallet")]
    pub(crate) fn of_raster(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl RegisteredType {
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
}

impl RegisteredCredential {
    /// The type, with its format.
    pub fn credential_type(&self) -> &RegisteredType {
        &self.credential_type
    }

    /// The claims.
    pub fn claims(&self) -> &ClaimTree {
        &self.claims
    }

    /// The card.
    pub fn card(&self) -> &RegisteredCard {
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
    pub fn transactions(&self) -> &ServedTypes<Projected> {
        &self.transactions
    }
}

impl RegisteredCard {
    /// The title.
    pub fn title(&self) -> &CardText {
        &self.title
    }

    /// The issuer line.
    pub fn issuer(&self) -> &CardText {
        &self.issuer
    }

    /// The icon.
    pub fn icon(&self) -> &Icon {
        &self.icon
    }
}

impl Instance for &RegisteredCredential {
    fn entry(&self) -> EntryRef {
        self.entry
    }
}

/// A credential of the registration, matched with the issuer facts it carries (TR5).
impl MatchCredential for &RegisteredCredential {
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

/// The definitions the credential's sources serve, as the wallet recorded them.
impl Definitions for RegisteredCredential {
    fn serve(&self, entry: &Entry) -> Result<Projected, Incompatibility> {
        self.transactions
            .serve(entry.type_id())
            .cloned()
            .map_err(Incompatibility::Registered)
    }
}
