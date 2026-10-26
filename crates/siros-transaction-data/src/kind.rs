//! The transaction data types (T2): what each type owns, and the registry of the supported
//! ones.

use siros_credential::Format;
use siros_display::Locale;

use crate::binding::Binding;
use crate::error::TransactionDataError;
use crate::json::Fields;
use crate::labels::DisplayMetadata;
use crate::metadata::TypeMetadata;
use crate::ts12::{AccountAccess, Emandate, LoginRisk, Payload, Payment, Ts12};
use crate::view::TransactionView;

/// One transaction data type, as an entry of it. Its parser, the registry's [`Parse`], reads
/// its members into typed values (OpenID4VP 1.0, Section 8.5).
pub(crate) trait TransactionType {
    /// The `type` value.
    fn identifier(&self) -> &'static str;

    /// The format of the credentials that can authorize it.
    fn format(&self) -> Format;

    /// Whether the credential of `metadata` can authorize it.
    fn authorizes(&self, metadata: &TypeMetadata<'_>) -> bool;

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

/// The parser of a type: from the members of an entry besides `type` and `credential_ids`.
type Parse = fn(Fields) -> Result<Box<dyn TransactionType>, TransactionDataError>;

/// The supported types (T6).
const REGISTRY: [(&str, Parse); 4] = [
    (Payment::TYPE, Ts12::<Payment>::parse),
    (LoginRisk::TYPE, Ts12::<LoginRisk>::parse),
    (AccountAccess::TYPE, Ts12::<AccountAccess>::parse),
    (Emandate::TYPE, Ts12::<Emandate>::parse),
];

/// The entry of type `identifier` of `fields`.
///
/// # Errors
///
/// [`TransactionDataError::UnsupportedType`] for a type the registry lacks, else the first rule
/// of the type `fields` breaks.
pub(crate) fn parse(
    identifier: &str,
    fields: Fields,
) -> Result<Box<dyn TransactionType>, TransactionDataError> {
    let (_, parse) = REGISTRY
        .iter()
        .find(|(supported, _)| *supported == identifier)
        .ok_or(TransactionDataError::UnsupportedType)?;
    parse(fields)
}

/// The supported type named `identifier`.
pub(crate) fn supported(identifier: &str) -> Option<&'static str> {
    REGISTRY
        .iter()
        .map(|(supported, _)| *supported)
        .find(|supported| *supported == identifier)
}
