//! Payload conformance (PaSO Core, Section 7.4.2, step 2; PaSO View, Section 3): every field
//! covered by a claim, every mandatory claim present, every value of a displayed claim of its
//! value type, and every string free of directional overrides.

mod pointer;
mod time;
mod values;

use siros_codec::json::Json;
use siros_dcql::PathError;

use crate::definition::{ClaimIndex, Definition, Mandatory, TextFault};
use crate::image::ImageFault;

pub use pointer::{Location, Step};
pub use time::{IsoDateTime, IsoTime};
pub use values::{CurrencyAmount, Frequency, NumberText, PayloadText, Scalar, Typed};

pub(crate) use pointer::{select, Selected};
pub(crate) use values::{scalar, typed};

/// The suffix of the member that carries a sibling image's integrity metadata (PaSO View,
/// Section 3, `image`).
pub(crate) const INTEGRITY_SUFFIX: &str = "#integrity";

/// Why a payload does not conform to a definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadFault {
    /// The field at this location is covered by no claim's `path` (Core, Section 7.4.2).
    Uncovered(Location),
    /// The mandatory claim at this position is absent.
    MandatoryAbsent(ClaimIndex),
    /// Processing the `path` of the claim at this position aborts (OpenID4VP 1.0, Section
    /// 7.1.1).
    Path(ClaimIndex, PathError),
    /// The value at this location of the claim at this position does not conform to its value
    /// type.
    Value(ClaimIndex, Location, ValueFault),
    /// The string at this location breaks a directional rule (Proof Metadata, Section 3.3).
    Text(Location, TextFault),
}

/// Why a value does not conform to its claim's value type (PaSO View, Section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueFault {
    /// A value without a value type, or of a string type, is no string.
    NotString,
    /// The value is no value of this type.
    Type(crate::definition::BaseType),
    /// The image reference breaks a rule.
    Image(ImageFault),
    /// The string breaks a directional rule (Proof Metadata, Section 3.3).
    Text(TextFault),
}

impl PayloadFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Uncovered(_) => "payload_field_uncovered",
            Self::MandatoryAbsent(_) => "payload_mandatory_absent",
            Self::Path(..) => "payload_path",
            Self::Value(_, _, fault) => fault.code(),
            Self::Text(_, fault) => fault.code(),
        }
    }
}

impl ValueFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotString => "payload_value_not_string",
            Self::Type(_) => "payload_value_type",
            Self::Image(fault) => fault.code(),
            Self::Text(fault) => fault.code(),
        }
    }
}

siros_codec::display_code!(PayloadFault, ValueFault);

impl std::error::Error for PayloadFault {}

/// The typed value of each displayed claim instance of a payload, by location.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values(Vec<(Location, Typed)>);

impl Values {
    /// The values `values`.
    pub(crate) fn new(values: Vec<(Location, Typed)>) -> Self {
        Self(values)
    }

    /// The value at `location`.
    pub(crate) fn get(&self, location: &Location) -> Option<&Typed> {
        self.0
            .iter()
            .find(|(at, _)| at == location)
            .map(|(_, value)| value)
    }

    /// The values, in the order of the claims and of the payload's arrays.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &(Location, Typed)> {
        self.0.iter()
    }
}

/// The values of `payload`, the members of a `payload` object, that conform to `definition`.
///
/// # Errors
///
/// [`PayloadFault`]: the first rule the payload breaks, in this order: the strings' directional
/// rules, the coverage of every field, then each claim in order.
pub(crate) fn conform(payload: &Json, definition: &Definition) -> Result<Values, PayloadFault> {
    let mut fields = Vec::new();
    leaves(payload, &Location::default(), &mut fields)?;
    let paths: Vec<_> = definition
        .claims()
        .iter()
        .map(|claim| claim.path().components())
        .collect();
    // A field is covered by a claim that addresses it or what contains it, and an empty object
    // or array by a claim that addresses what it would contain.
    let covered = |location: &Location| {
        paths
            .iter()
            .any(|path| location.covered_by(path) || location.leads_to(path))
    };
    if let Some(uncovered) = fields.iter().find(|location| {
        !covered(location) && !integrity_companion(location).is_some_and(|of| covered(&of))
    }) {
        return Err(PayloadFault::Uncovered(uncovered.clone()));
    }
    let mut values = Vec::new();
    for (at, claim) in definition.claims().iter().enumerate() {
        let index = ClaimIndex::new(at);
        let selected = select(payload, claim.path().components())
            .map_err(|error| PayloadFault::Path(index, error))?;
        if selected.is_empty() && claim.mandatory() == Mandatory::Required {
            return Err(PayloadFault::MandatoryAbsent(index));
        }
        if claim.display().is_none() {
            continue;
        }
        for Selected {
            location, value, ..
        } in selected
        {
            let integrity = integrity_of(payload, &location);
            let value = typed(value, claim.value_type(), integrity)
                .map_err(|fault| PayloadFault::Value(index, location.clone(), fault))?;
            values.push((location, value));
        }
    }
    Ok(Values::new(values))
}

/// Adds the location of each field under `value`, at `location`, to `fields`: each value that
/// is no object or array with members, and checks each string's directional rules.
fn leaves(
    value: &Json,
    location: &Location,
    fields: &mut Vec<Location>,
) -> Result<(), PayloadFault> {
    match value {
        Json::Object(members) if !members.is_empty() => {
            members.iter().try_for_each(|(name, member)| {
                leaves(member, &location.then(Step::Key(name.clone())), fields)
            })
        }
        Json::Array(items) if !items.is_empty() => (0u64..)
            .zip(items)
            .try_for_each(|(at, item)| leaves(item, &location.then(Step::Index(at)), fields)),
        Json::String(text) => {
            crate::definition::bidi(text)
                .map_err(|fault| PayloadFault::Text(location.clone(), fault))?;
            fields.push(location.clone());
            Ok(())
        }
        Json::Null | Json::Bool(_) | Json::Number(_) | Json::Object(_) | Json::Array(_) => {
            fields.push(location.clone());
            Ok(())
        }
    }
}

/// The location of the member `location` accompanies when it is a `#integrity` companion: the
/// sibling named without the suffix.
fn integrity_companion(location: &Location) -> Option<Location> {
    let name = location.last_key()?.strip_suffix(INTEGRITY_SUFFIX)?;
    location.sibling(name)
}

/// The value of the `#integrity` sibling of the member at `location`.
pub(crate) fn integrity_of<'j>(payload: &'j Json, location: &Location) -> Option<&'j Json> {
    let name = format!("{}{INTEGRITY_SUFFIX}", location.last_key()?);
    let sibling = location.sibling(&name)?;
    let mut value = payload;
    for step in sibling.steps() {
        value = match (step, value) {
            (Step::Key(key), Json::Object(members)) => {
                &members.iter().find(|(name, _)| name == key)?.1
            }
            (Step::Index(index), Json::Array(items)) => items.get(usize::try_from(*index).ok()?)?,
            (Step::Key(_) | Step::Index(_), _) => return None,
        };
    }
    Some(value)
}
