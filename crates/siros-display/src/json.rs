//! Reading members of metadata objects.

use serde_json::{Map, Value};

use crate::colour::Colour;
use crate::error::DisplayError;
use crate::locale::Locale;
use crate::text::DisplayText;

/// The object `value`.
pub(crate) fn object(value: &Value) -> Result<&Map<String, Value>, DisplayError> {
    value.as_object().ok_or(DisplayError::NotObject)
}

/// The string member `name`; `None` when absent.
pub(crate) fn string<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    malformed: DisplayError,
) -> Result<Option<&'a str>, DisplayError> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(malformed),
    }
}

/// The string member `name` as a label; `None` when absent.
pub(crate) fn label(
    object: &Map<String, Value>,
    name: &str,
    malformed: DisplayError,
) -> Result<Option<DisplayText>, DisplayError> {
    string(object, name, malformed)?
        .map(|text| DisplayText::label(text).map_err(DisplayError::Text))
        .transpose()
}

/// The language tag `locale`; `None` when absent.
pub(crate) fn locale(
    object: &Map<String, Value>,
    malformed: DisplayError,
) -> Result<Option<Locale>, DisplayError> {
    string(object, "locale", malformed)?
        .map(|tag| Locale::parse(tag).map_err(DisplayError::Locale))
        .transpose()
}

/// The colour member `name`; `None` when absent.
pub(crate) fn colour(
    object: &Map<String, Value>,
    name: &str,
) -> Result<Option<Colour>, DisplayError> {
    string(object, name, DisplayError::Colour)?
        .map(Colour::parse)
        .transpose()
}

/// The array member `name`, non-empty when `non_empty`; `None` when absent.
pub(crate) fn array<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    non_empty: bool,
    malformed: DisplayError,
) -> Result<Option<&'a [Value]>, DisplayError> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::Array(items)) if !(non_empty && items.is_empty()) => Ok(Some(items)),
        Some(_) => Err(malformed),
    }
}

/// Each entry has a different locale, or none (OpenID4VCI 1.0, Section 12.2.4; SD-JWT VC,
/// Sections 5.5 and 5.6.2).
pub(crate) fn distinct_locales<'a>(
    locales: impl Iterator<Item = Option<&'a Locale>>,
) -> Result<(), DisplayError> {
    let mut seen: Vec<&Locale> = Vec::new();
    for locale in locales.flatten() {
        if seen.contains(&locale) {
            return Err(DisplayError::DisplayLocaleRepeated);
        }
        seen.push(locale);
    }
    Ok(())
}
