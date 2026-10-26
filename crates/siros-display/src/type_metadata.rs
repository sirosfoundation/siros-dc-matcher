//! SD-JWT VC Type Metadata (SD-JWT VC draft 19, Section 5).

use rustc_hash::FxHashSet;
use serde_json::{Map, Value};
use siros_dcql::PathComponent;

use crate::claims::{self, Label};
use crate::entry::DisplayEntry;
use crate::error::DisplayError;
use crate::json;
use crate::locale::Localized;
use crate::logo;

/// The Type Metadata of one `vct`: its display and its claim labels.
#[derive(Debug, Clone)]
pub struct TypeMetadata {
    vct: String,
    extends: Option<String>,
    display: Option<Vec<DisplayEntry>>,
    claims: Vec<TypeClaim>,
}

/// A claim metadata object (Section 5.6): its path, and its labels when it has `display`.
#[derive(Debug, Clone)]
pub(crate) struct TypeClaim {
    pub(crate) path: Vec<PathComponent>,
    pub(crate) labels: Option<Vec<Label>>,
}

impl TypeMetadata {
    /// The Type Metadata document `document` (Section 5.2).
    ///
    /// `vct` is a string and `extends` a string. `display` is an array of objects, each with a
    /// `locale` and a string `name`, one per locale, and an optional `rendering.simple` whose
    /// `logo`, `background_color` and `text_color` are read. `claims` is an array of claim
    /// metadata objects, each with a `path`, a `display` array of objects with a `locale` and a
    /// string `label` (one per locale), a boolean `mandatory`, an `sd` of `always`, `allowed` or
    /// `never`, and an `svg_id` of ASCII letters, digits and `_` that starts with no digit and is
    /// unique in the document (Section 5.6). Other members are ignored.
    ///
    /// # Errors
    ///
    /// [`DisplayError`]: the first rule `document` breaks.
    pub fn parse(document: &Value) -> Result<Self, DisplayError> {
        let object = json::object(document)?;
        let vct = json::string(object, "vct", DisplayError::Vct)?.ok_or(DisplayError::Vct)?;
        let extends = json::string(object, "extends", DisplayError::Extends)?;
        let display = json::array(object, "display", false, DisplayError::Display)?
            .map(|entries| {
                entries
                    .iter()
                    .map(type_display)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        if let Some(display) = &display {
            json::distinct_locales(display.iter().map(Localized::locale))?;
        }
        let entries = json::array(object, "claims", false, DisplayError::Claims)?;
        let mut svg_ids = FxHashSet::default();
        let claims = entries
            .unwrap_or_default()
            .iter()
            .map(|claim| type_claim(claim, &mut svg_ids))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            vct: vct.to_owned(),
            extends: extends.map(str::to_owned),
            display,
            claims,
        })
    }

    /// The `vct` the document describes.
    pub fn vct(&self) -> &str {
        &self.vct
    }

    /// The `vct` of the type this one extends (Section 5.4).
    pub(crate) fn extends(&self) -> Option<&str> {
        self.extends.as_deref()
    }

    /// The `display` entries. `None` when the document has no `display`, and inherits it
    /// (Section 5.5.2).
    pub(crate) fn display(&self) -> Option<&[DisplayEntry]> {
        self.display.as_deref()
    }

    /// The claim metadata objects.
    pub(crate) fn claims(&self) -> &[TypeClaim] {
        &self.claims
    }
}

fn type_display(entry: &Value) -> Result<DisplayEntry, DisplayError> {
    let entry = entry.as_object().ok_or(DisplayError::Display)?;
    let locale = json::locale(entry, DisplayError::Display)?.ok_or(DisplayError::Display)?;
    let name = json::label(entry, "name", DisplayError::Display)?.ok_or(DisplayError::Display)?;
    let empty = Map::new();
    let simple = match entry.get("rendering") {
        None => &empty,
        Some(rendering) => match json::object(rendering)?.get("simple") {
            None => &empty,
            Some(simple) => json::object(simple)?,
        },
    };
    Ok(DisplayEntry {
        locale: Some(locale),
        name,
        logo: logo::optional(simple)?,
        background: json::colour(simple, "background_color")?,
        text: json::colour(simple, "text_color")?,
    })
}

fn type_claim(claim: &Value, svg_ids: &mut FxHashSet<String>) -> Result<TypeClaim, DisplayError> {
    let claim = claim.as_object().ok_or(DisplayError::Claims)?;
    let path = claims::path(claim.get("path"))?;
    match claim.get("mandatory") {
        None | Some(Value::Bool(_)) => {}
        Some(_) => return Err(DisplayError::Mandatory),
    }
    match json::string(claim, "sd", DisplayError::Sd)? {
        None | Some("always" | "allowed" | "never") => {}
        Some(_) => return Err(DisplayError::Sd),
    }
    if let Some(svg_id) = json::string(claim, "svg_id", DisplayError::SvgId)? {
        let syntax = svg_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && svg_id.bytes().next().is_some_and(|b| !b.is_ascii_digit());
        if !syntax || !svg_ids.insert(svg_id.to_owned()) {
            return Err(DisplayError::SvgId);
        }
    }
    let labels = json::array(claim, "display", false, DisplayError::Claims)?
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    let entry = entry.as_object().ok_or(DisplayError::Claims)?;
                    let locale =
                        json::locale(entry, DisplayError::Claims)?.ok_or(DisplayError::Claims)?;
                    let text = json::label(entry, "label", DisplayError::Claims)?
                        .ok_or(DisplayError::Claims)?;
                    Ok(Label {
                        locale: Some(locale),
                        text,
                    })
                })
                .collect::<Result<Vec<_>, DisplayError>>()
        })
        .transpose()?;
    if let Some(labels) = &labels {
        json::distinct_locales(labels.iter().map(Localized::locale))?;
    }
    Ok(TypeClaim { path, labels })
}
