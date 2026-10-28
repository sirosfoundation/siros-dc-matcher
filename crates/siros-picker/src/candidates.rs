//! The credentials a request asks for, read from the registration: the records of the types
//! its queries ask for, each with the definitions the request's entries name for it.

use std::io::{Read, Seek};

use siros_dcql::QueryId;
use siros_presentation::{QueryTypes, RequestEntries};
use siros_registration::{RegisteredCredential, RegisteredType, Registration, RegistrationError};
use siros_transaction_data::{Projected, TypeId};

/// A credential a request asks for, with the definitions its sources serve for the types the
/// request's entries name for it.
pub(crate) type Requested = RegisteredCredential<Projected>;

/// The credentials of the types `asked` gives each query, in the wallet's order, each with the
/// definitions read that its sources serve for the types of [`named_types`].
///
/// # Errors
///
/// [`RegistrationError`]: a part read that breaks a rule of the registration.
pub(crate) fn read<R: Read + Seek>(
    registration: &mut Registration<R>,
    asked: &[QueryTypes],
    entries: Option<&RequestEntries>,
) -> Result<Vec<Requested>, RegistrationError> {
    let types: Vec<RegisteredType> = asked
        .iter()
        .flat_map(QueryTypes::types)
        .map(RegisteredType::from)
        .collect();
    registration
        .credentials(&types)?
        .into_iter()
        .map(|credential| {
            let named = named_types(credential.credential_type(), asked, entries);
            credential.select(&named, |at| registration.definition(*at))
        })
        .collect()
}

/// The types of the entries of `entries` that a registered definition may serve for a
/// credential of `credential_type`: those of the entries that target a query asking for the
/// type, without ad-hoc metadata, which the selection defers to the wallet.
fn named_types(
    credential_type: &RegisteredType,
    asked: &[QueryTypes],
    entries: Option<&RequestEntries>,
) -> Vec<TypeId> {
    let asking: Vec<&QueryId> = asked
        .iter()
        .filter(|query| query.types().iter().any(|asked| credential_type == asked))
        .map(QueryTypes::query)
        .collect();
    entries
        .into_iter()
        .flat_map(RequestEntries::entries)
        .filter(|entry| entry.metadata().is_none())
        .filter(|entry| asking.iter().any(|query| entry.names(query)))
        .map(|entry| entry.type_id().clone())
        .collect()
}
