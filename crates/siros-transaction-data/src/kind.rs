//! The transaction data types (T2): what each type owns, and the registry of the supported
//! ones.

use siros_codec::date::DateTime;
use siros_credential::Format;
use siros_display::Locale;

use crate::binding::Binding;
use crate::error::TransactionDataError;
use crate::json::Fields;
use crate::labels::DisplayMetadata;
use crate::metadata::ScaMetadata;
use crate::ts12::{AccountAccess, Emandate, LoginRisk, Payment, Ts12};
use crate::view::TransactionView;

/// One transaction data type, as an entry of it. Its parser, [`SupportedType::parse`], reads
/// its members into typed values (OpenID4VP 1.0, Section 8.5).
pub(crate) trait TransactionType {
    /// The `type` value.
    fn identifier(&self) -> SupportedType;

    /// The format of the credentials that can authorize it.
    fn format(&self) -> Format;

    /// Whether the credential of `metadata` can authorize it.
    fn authorizes(&self, metadata: &ScaMetadata<'_>) -> bool;

    /// What it binds into the presentation of the credential that authorizes it: its
    /// B.3.3.1 hash and the KB-JWT claims its specification requires.
    fn binding(&self) -> Binding<'_>;

    /// Its display, from the display metadata of its type and the user's locale
    /// `preferences`, most preferred first.
    fn display(
        &self,
        metadata: &DisplayMetadata,
        preferences: &[Locale],
    ) -> Result<TransactionView, TransactionDataError>;
}

/// A transaction data type this wallet supports (T6): the four types of EC TS12 v1.0.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupportedType {
    /// `urn:eudi:sca:payment:1`.
    Payment,
    /// `urn:eudi:sca:login_risk_transaction:1`.
    LoginRisk,
    /// `urn:eudi:sca:account_access:1`.
    AccountAccess,
    /// `urn:eudi:sca:emandate:1`.
    Emandate,
}

impl SupportedType {
    const ALL: [Self; 4] = [
        Self::Payment,
        Self::LoginRisk,
        Self::AccountAccess,
        Self::Emandate,
    ];

    /// The `type` value.
    #[must_use]
    pub fn identifier(self) -> &'static str {
        match self {
            Self::Payment => "urn:eudi:sca:payment:1",
            Self::LoginRisk => "urn:eudi:sca:login_risk_transaction:1",
            Self::AccountAccess => "urn:eudi:sca:account_access:1",
            Self::Emandate => "urn:eudi:sca:emandate:1",
        }
    }

    /// The supported type the `type` value `identifier` names.
    pub(crate) fn named(identifier: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|supported| supported.identifier() == identifier)
    }

    /// The entry of this type of `fields`, the members of an entry besides `type` and
    /// `credential_ids`, at the time `now`.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: the first rule of the type `fields` breaks.
    pub(crate) fn parse(
        self,
        fields: Fields,
        now: DateTime,
    ) -> Result<Box<dyn TransactionType>, TransactionDataError> {
        match self {
            Self::Payment => Ts12::<Payment>::parse(fields, now),
            Self::LoginRisk => Ts12::<LoginRisk>::parse(fields, now),
            Self::AccountAccess => Ts12::<AccountAccess>::parse(fields, now),
            Self::Emandate => Ts12::<Emandate>::parse(fields, now),
        }
    }
}
