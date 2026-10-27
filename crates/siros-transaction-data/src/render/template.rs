//! `template:` interpolation (PaSO View, Section 3): `{<index>}` placeholders replaced, in one
//! pass, by the value of the claim at that position of the `claims` array.

use siros_codec::json::Json;

use crate::definition::{BaseType, ClaimIndex, ValueType};
use crate::payload::{select, Location, Typed, Values};
use crate::projection::ProjectedClaim;

/// Why a template does not interpolate. The entry is then not compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateFault {
    /// The placeholder names the claim at this position, which is an `image`, a `label_only`
    /// or a `template:` claim.
    Reference(ClaimIndex),
    /// The claim at this position has more `null`s in its path than the referencing claim.
    Wildcards(ClaimIndex),
    /// The claim at this position has no value type, and its value is no string.
    NotString(ClaimIndex),
    /// The claim at this position is absent from the payload: the locale entry is discarded,
    /// and no other locale is left.
    Absent(ClaimIndex),
    /// The interpolated value is no value of the template's inner type, or the inner type is
    /// `image` or `boolean`, which no string formats as.
    Inner(BaseType),
}

impl TemplateFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Reference(_) => "template_reference",
            Self::Wildcards(_) => "template_wildcards",
            Self::NotString(_) => "template_not_string",
            Self::Absent(_) => "template_absent",
            Self::Inner(_) => "template_inner",
        }
    }
}

siros_codec::display_code!(TemplateFault);

impl std::error::Error for TemplateFault {}

/// What a template reads: the claims, the payload and its typed values.
pub(super) struct Sources<'s> {
    pub(super) claims: &'s [ProjectedClaim],
    pub(super) payload: &'s Json,
    pub(super) values: &'s Values,
}

/// The text of `template` with each placeholder replaced, `wildcards` the array positions the
/// `null`s of the referencing claim's path took. A placeholder past the end of `claims` stays
/// as written, and a replaced value is never read again.
///
/// # Errors
///
/// [`TemplateFault`]: the first placeholder that does not resolve.
pub(super) fn interpolate(
    template: &str,
    wildcards: &[u64],
    sources: &Sources<'_>,
) -> Result<String, TemplateFault> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let (before, from) = rest.split_at(open);
        out.push_str(before);
        let placeholder = from.get(1..).and_then(|tail| {
            let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
            let index: usize = tail.get(..digits)?.parse().ok()?;
            tail.get(digits..)?
                .strip_prefix('}')
                .map(|after| (index, after))
        });
        match placeholder.filter(|(index, _)| *index < sources.claims.len()) {
            Some((index, after)) => {
                out.push_str(&value(ClaimIndex::new(index), wildcards, sources)?);
                rest = after;
            }
            None => {
                out.push('{');
                rest = from.get(1..).unwrap_or_default();
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// The text of the value of the claim at `index`, its `null`s resolved to `wildcards`.
fn value(
    index: ClaimIndex,
    wildcards: &[u64],
    sources: &Sources<'_>,
) -> Result<String, TemplateFault> {
    let claim = sources
        .claims
        .get(index.value())
        .map(ProjectedClaim::definition)
        .ok_or(TemplateFault::Absent(index))?;
    match claim.value_type() {
        Some(ValueType::Template(_))
        | Some(ValueType::Plain(BaseType::Image | BaseType::LabelOnly)) => {
            return Err(TemplateFault::Reference(index))
        }
        Some(ValueType::Plain(_)) | None => {}
    }
    let count = claim.path().wildcards();
    let bound = wildcards
        .get(..count)
        .ok_or(TemplateFault::Wildcards(index))?;
    let location =
        Location::bound(claim.path().components(), bound).ok_or(TemplateFault::Wildcards(index))?;
    match sources.values.get(&location) {
        Some(Typed::Scalar(scalar)) => return Ok(scalar.text()),
        Some(Typed::Image(_) | Typed::LabelOnly | Typed::Template(..)) => {
            return Err(TemplateFault::Reference(index))
        }
        None => {}
    }
    // An internal claim: its value is a string of the payload.
    let selected = select(sources.payload, claim.path().components())
        .map_err(|_| TemplateFault::Absent(index))?;
    match selected
        .iter()
        .find(|selected| selected.location == location)
        .map(|selected| selected.value)
    {
        Some(Json::String(text)) => Ok(text.clone()),
        Some(_) => Err(TemplateFault::NotString(index)),
        None => Err(TemplateFault::Absent(index)),
    }
}
