//! Claim rows: a label and a typed value per claim (D2 to D5).

use siros_codec::date::{Date, DateTime};
use siros_credential::{ClaimPointer, Credential, TypedValue};
use siros_dcql::PathComponent;

use crate::cache::DisplayCache;
use crate::claims::{describes, ClaimDescription, Label};
use crate::error::DisplayError;
use crate::locale::{choose, Locale};
use crate::text::DisplayText;
use crate::type_metadata::TypeMetadata;

/// A claim as the user sees it: its label and its value.
#[derive(Clone, PartialEq)]
pub struct ClaimRow {
    label: DisplayText,
    value: DisplayValue,
}

impl ClaimRow {
    /// The label.
    pub fn label(&self) -> &DisplayText {
        &self.label
    }

    /// The value.
    pub fn value(&self) -> &DisplayValue {
        &self.value
    }
}

/// A claim value, typed for display (D4). The UI formats numbers and dates for its locale.
#[derive(Clone, PartialEq)]
pub enum DisplayValue {
    /// `null`.
    Null,
    /// A boolean.
    Boolean(bool),
    /// An integer.
    Integer(i128),
    /// A number with a fraction or an exponent.
    Number(f64),
    /// Text, as the credential holds it.
    Text(String),
    /// A calendar date.
    Date(Date),
    /// A date and time in UTC.
    DateTime(DateTime),
    /// A byte string, shown by its length in bytes (D5).
    Bytes(usize),
    /// The elements of an array that the credential holds, in order.
    List(Vec<DisplayValue>),
    /// The members of an object, each with its label, in order.
    Group(Vec<ClaimRow>),
}

/// The claim descriptions and preferences that label the rows of one credential.
struct Labels<'a> {
    issuer: &'a [ClaimDescription],
    types: Vec<&'a TypeMetadata>,
    preferences: &'a [Locale],
}

impl DisplayCache {
    /// The rows of the claims `pointers` select in `credential`, one per pointer, for the
    /// user's `preferences`, most preferred first.
    ///
    /// A row's label comes from the claims descriptions of the credential's configuration and
    /// of its Type Metadata that address the row's path: [`choose`] takes it from the OpenID4VCI
    /// labels followed by those of the nearest type with a labelled description, so that an
    /// OpenID4VCI label wins for the same locale (D3). Without any label it is the path's last
    /// key. A pointer with a `null` gives a [`DisplayValue::List`] of the values it selects. An
    /// object gives a [`DisplayValue::Group`] of rows, labelled at the member's path; an
    /// array's elements are at its path extended with `null`. A byte string shows its length
    /// (D5): no display metadata of the ecosystem declares a claim to be an image.
    ///
    /// # Errors
    ///
    /// [`DisplayError::Pointer`] for a pointer that selects nothing in `credential`, and the
    /// other [`DisplayError`]s for a label that is no safe label or for a value with no display
    /// type.
    pub fn claim_rows(
        &self,
        credential: &Credential,
        pointers: &[ClaimPointer],
        preferences: &[Locale],
    ) -> Result<Vec<ClaimRow>, DisplayError> {
        let labels = Labels {
            issuer: self
                .issued(credential)
                .map(|metadata| metadata.claims())
                .unwrap_or_default(),
            types: self.types_of(credential),
            preferences,
        };
        pointers
            .iter()
            .map(|pointer| {
                let path = pointer.components();
                let values = credential.claims(pointer).map_err(DisplayError::Pointer)?;
                let value = if path.contains(&PathComponent::Null) {
                    let elements = values.into_iter().map(|value| labels.value(path, value));
                    DisplayValue::List(elements.collect::<Result<_, _>>()?)
                } else {
                    match values.as_slice() {
                        [value] => labels.value(path, *value)?,
                        _ => return Err(DisplayError::PointerSelectsSeveral),
                    }
                };
                Ok(ClaimRow {
                    label: labels.label(path)?,
                    value,
                })
            })
            .collect()
    }
}

impl Labels<'_> {
    /// The label of the claims at `path`.
    fn label(&self, path: &[PathComponent]) -> Result<DisplayText, DisplayError> {
        let issuer = self
            .issuer
            .iter()
            .find(|description| describes(&description.path, path))
            .map(|description| description.labels.as_slice())
            .unwrap_or_default();
        let types = self
            .types
            .iter()
            .find_map(|metadata| {
                metadata
                    .claims()
                    .iter()
                    .filter(|claim| describes(&claim.path, path))
                    .find_map(|claim| claim.labels.as_deref())
            })
            .unwrap_or_default();
        let candidates: Vec<&Label> = issuer.iter().chain(types).collect();
        if let Some(label) = choose(self.preferences, &candidates) {
            return Ok(label.text.clone());
        }
        let key = path
            .iter()
            .rev()
            .find_map(PathComponent::as_key)
            .ok_or(DisplayError::PointerUnlabelled)?;
        DisplayText::label(key).map_err(DisplayError::Text)
    }

    /// `value`, the claim at `path`, for display.
    fn value(
        &self,
        path: &[PathComponent],
        value: TypedValue<'_>,
    ) -> Result<DisplayValue, DisplayError> {
        let extended = |component: PathComponent| {
            let mut extended = path.to_vec();
            extended.push(component);
            extended
        };
        Ok(match value {
            TypedValue::Null => DisplayValue::Null,
            TypedValue::Bool(b) => DisplayValue::Boolean(b),
            TypedValue::Integer(i) => DisplayValue::Integer(i),
            TypedValue::Number(n) => {
                DisplayValue::Number(n.as_f64().ok_or(DisplayError::NumberUnrepresentable)?)
            }
            TypedValue::Text(text) => DisplayValue::Text(text.to_owned()),
            TypedValue::Bytes(bytes) => DisplayValue::Bytes(bytes.len()),
            TypedValue::FullDate(date) => DisplayValue::Date(date),
            TypedValue::DateTime(time) => DisplayValue::DateTime(time),
            TypedValue::Array(array) => {
                let element = extended(PathComponent::Null);
                let elements = array.elements().map(|value| self.value(&element, value));
                DisplayValue::List(elements.collect::<Result<_, _>>()?)
            }
            TypedValue::Object(object) => {
                let members = object.members().map(|(name, value)| {
                    let member = extended(PathComponent::Key(name.to_owned()));
                    Ok(ClaimRow {
                        label: self.label(&member)?,
                        value: self.value(&member, value)?,
                    })
                });
                DisplayValue::Group(members.collect::<Result<_, DisplayError>>()?)
            }
        })
    }
}
