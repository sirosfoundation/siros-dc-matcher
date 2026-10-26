//! Claim descriptions: the labels display metadata gives the claims at a path.

use serde_json::Value;
use siros_dcql::PathComponent;

use crate::error::DisplayError;
use crate::json;
use crate::locale::{Locale, Localized};
use crate::text::DisplayText;

/// A claim label in one locale, or in an unstated one.
#[derive(Debug, Clone)]
pub(crate) struct Label {
    pub(crate) locale: Option<Locale>,
    pub(crate) text: DisplayText,
}

impl Localized for Label {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}

/// A claims description of OpenID4VCI issuer metadata (OpenID4VCI 1.0, Appendix B.2): the
/// path, and a label for each `display` entry that has a `name`.
#[derive(Debug, Clone)]
pub(crate) struct ClaimDescription {
    pub(crate) path: Vec<PathComponent>,
    pub(crate) labels: Vec<Label>,
}

/// The claims descriptions of `claims`, a non-empty array (OpenID4VCI 1.0, Section 12.2.4).
///
/// Each has a `path` and an optional non-empty `display` array of objects with an optional
/// `name` and an optional `locale`, one object per locale. No two describe the same claim, and
/// no two contradict each other (Appendix B.3).
pub(crate) fn issuer_claims(claims: &[Value]) -> Result<Vec<ClaimDescription>, DisplayError> {
    let described = claims
        .iter()
        .map(|claim| {
            let claim = claim.as_object().ok_or(DisplayError::Claims)?;
            let path = path(claim.get("path"))?;
            let entries = json::array(claim, "display", true, DisplayError::Claims)?;
            let mut labels = Vec::new();
            let mut locales = Vec::new();
            for entry in entries.unwrap_or_default() {
                let entry = entry.as_object().ok_or(DisplayError::Claims)?;
                let locale = json::locale(entry, DisplayError::Claims)?;
                let name = json::label(entry, "name", DisplayError::Claims)?;
                locales.push(locale.clone());
                if let Some(text) = name {
                    labels.push(Label { locale, text });
                }
            }
            json::distinct_locales(locales.iter().map(Option::as_ref))?;
            Ok(ClaimDescription { path, labels })
        })
        .collect::<Result<Vec<_>, DisplayError>>()?;
    consistent(&described)?;
    Ok(described)
}

/// No path addresses the claim another addresses, and no two paths disagree on whether a claim
/// is an object or an array, or address one array both by `null` and by an index (OpenID4VCI
/// 1.0, Appendix B.3).
fn consistent(described: &[ClaimDescription]) -> Result<(), DisplayError> {
    for (at, first) in described.iter().enumerate() {
        for second in described.iter().skip(at + 1) {
            let differing = first.path.iter().zip(&second.path).find(|(a, b)| a != b);
            match differing {
                None if first.path.len() == second.path.len() => {
                    return Err(DisplayError::ClaimRepeated)
                }
                None => {}
                Some((a, b)) => {
                    let key = |c: &PathComponent| matches!(c, PathComponent::Key(_));
                    let null = |c: &PathComponent| matches!(c, PathComponent::Null);
                    if key(a) != key(b) || null(a) != null(b) {
                        return Err(DisplayError::ClaimContradictory);
                    }
                }
            }
        }
    }
    Ok(())
}

/// A claims path pointer of display metadata: a non-empty array of strings, nulls and
/// non-negative integers (OpenID4VCI 1.0, Appendix C; SD-JWT VC, Section 5.6.1).
pub(crate) fn path(value: Option<&Value>) -> Result<Vec<PathComponent>, DisplayError> {
    let components = match value {
        Some(Value::Array(components)) if !components.is_empty() => components,
        _ => return Err(DisplayError::ClaimPath),
    };
    components
        .iter()
        .map(|component| match component {
            Value::String(key) => Ok(PathComponent::Key(key.clone())),
            Value::Null => Ok(PathComponent::Null),
            Value::Number(n) => n
                .as_u64()
                .map(PathComponent::Index)
                .ok_or(DisplayError::ClaimPath),
            _ => Err(DisplayError::ClaimPath),
        })
        .collect()
}

/// Whether the description path `described` addresses the claim at `path`: the same length,
/// equal keys and indexes, and `null` addressing any index or `null` of `path`.
pub(crate) fn describes(described: &[PathComponent], path: &[PathComponent]) -> bool {
    described.len() == path.len()
        && described.iter().zip(path).all(|(d, p)| match (d, p) {
            (PathComponent::Null, PathComponent::Index(_) | PathComponent::Null) => true,
            (d, p) => d == p,
        })
}
