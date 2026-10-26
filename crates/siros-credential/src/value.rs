//! Claim values with their type, read from the format's own tree (C2).

use serde_json::Number;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::{Date, DateTime};
use siros_sdjwt::{Claim, ClaimValue, Element};

use crate::error::ClaimError;

/// A claim value with its type.
#[derive(Clone, Copy)]
pub enum TypedValue<'a> {
    /// JSON `null`, CBOR `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// A JSON number without a fraction or exponent that fits 64 bits, or a CBOR integer.
    Integer(i128),
    /// Any other JSON number.
    Number(f64),
    /// A JSON string, a CBOR text string.
    Text(&'a str),
    /// A CBOR byte string.
    Bytes(&'a [u8]),
    /// A CBOR `full-date`: tag 1004 over `YYYY-MM-DD`.
    FullDate(Date),
    /// A CBOR `tdate`: tag 0 over `YYYY-MM-DDThh:mm:ssZ`.
    DateTime(DateTime),
    /// An array.
    Array(Array<'a>),
    /// An object, or a CBOR map whose keys are text.
    Object(Object<'a>),
}

/// An array value.
#[derive(Clone, Copy)]
pub struct Array<'a>(ArrayOf<'a>);

#[derive(Clone, Copy)]
enum ArrayOf<'a> {
    Json(&'a [Element]),
    Cbor(&'a [Cbor]),
}

/// An object value.
#[derive(Clone, Copy)]
pub struct Object<'a>(ObjectOf<'a>);

#[derive(Clone, Copy)]
enum ObjectOf<'a> {
    Json(&'a siros_sdjwt::Object),
    Cbor(&'a [(Cbor, Cbor)]),
}

impl<'a> Array<'a> {
    /// The elements the credential holds, in their order. An SD-JWT array element whose
    /// disclosure the credential lacks is absent.
    pub fn elements(&self) -> Elements<'a> {
        Elements(match self.0 {
            ArrayOf::Json(elements) => ElementsOf::Json(elements.iter()),
            ArrayOf::Cbor(items) => ElementsOf::Cbor(items.iter()),
        })
    }
}

impl<'a> Object<'a> {
    /// The members the credential holds, each with its name, in their order.
    pub fn members(&self) -> Members<'a> {
        Members(match self.0 {
            ObjectOf::Json(object) => MembersOf::Json(Box::new(object.members())),
            ObjectOf::Cbor(entries) => MembersOf::Cbor(entries.iter()),
        })
    }
}

/// The elements of an [`Array`].
pub struct Elements<'a>(ElementsOf<'a>);

enum ElementsOf<'a> {
    Json(std::slice::Iter<'a, Element>),
    Cbor(std::slice::Iter<'a, Cbor>),
}

impl<'a> Iterator for Elements<'a> {
    type Item = Result<TypedValue<'a>, ClaimError>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            ElementsOf::Json(elements) => elements
                .find_map(|element| match element {
                    Element::Present(claim) => Some(claim),
                    Element::Withheld => None,
                })
                .map(|claim| json(claim.value())),
            ElementsOf::Cbor(items) => items.next().map(cbor),
        }
    }
}

/// The members of an [`Object`].
pub struct Members<'a>(MembersOf<'a>);

enum MembersOf<'a> {
    Json(Box<dyn Iterator<Item = (&'a str, &'a Claim)> + 'a>),
    Cbor(std::slice::Iter<'a, (Cbor, Cbor)>),
}

impl<'a> Iterator for Members<'a> {
    type Item = Result<(&'a str, TypedValue<'a>), ClaimError>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            MembersOf::Json(members) => members
                .next()
                .map(|(name, claim)| Ok((name, json(claim.value())?))),
            MembersOf::Cbor(entries) => entries.next().map(|(key, value)| match key {
                Cbor::Text(name) => Ok((name.as_str(), cbor(value)?)),
                _ => Err(ClaimError::Untyped),
            }),
        }
    }
}

/// The processed SD-JWT payload as an object.
pub(crate) fn payload(object: &siros_sdjwt::Object) -> TypedValue<'_> {
    TypedValue::Object(Object(ObjectOf::Json(object)))
}

/// The SD-JWT claim value `value`.
pub(crate) fn json(value: &ClaimValue) -> Result<TypedValue<'_>, ClaimError> {
    Ok(match value {
        ClaimValue::Null => TypedValue::Null,
        ClaimValue::Bool(b) => TypedValue::Bool(*b),
        ClaimValue::Number(n) => number(n)?,
        ClaimValue::String(s) => TypedValue::Text(s),
        ClaimValue::Array(elements) => TypedValue::Array(Array(ArrayOf::Json(elements))),
        ClaimValue::Object(object) => payload(object),
    })
}

fn number(n: &Number) -> Result<TypedValue<'static>, ClaimError> {
    if let Some(i) = n.as_i64() {
        return Ok(TypedValue::Integer(i128::from(i)));
    }
    if let Some(u) = n.as_u64() {
        return Ok(TypedValue::Integer(i128::from(u)));
    }
    n.as_f64()
        .map(TypedValue::Number)
        .ok_or(ClaimError::Untyped)
}

/// The mdoc element value `value` (ISO/IEC 18013-5, 7.2.1: `tdate` is tag 0, `full-date` tag
/// 1004).
pub(crate) fn cbor(value: &Cbor) -> Result<TypedValue<'_>, ClaimError> {
    Ok(match value {
        Cbor::Unsigned(n) => TypedValue::Integer(i128::from(*n)),
        Cbor::Negative(n) => TypedValue::Integer(-1 - i128::from(*n)),
        Cbor::Bytes(b) => TypedValue::Bytes(b),
        Cbor::Text(t) => TypedValue::Text(t),
        Cbor::Array(items) => TypedValue::Array(Array(ArrayOf::Cbor(items))),
        Cbor::Map(entries) => TypedValue::Object(Object(ObjectOf::Cbor(entries))),
        Cbor::Tag(1004, inner) => match inner.as_ref() {
            Cbor::Text(t) => TypedValue::FullDate(Date::parse(t).ok_or(ClaimError::Untyped)?),
            _ => return Err(ClaimError::Untyped),
        },
        Cbor::Tag(0, inner) => match inner.as_ref() {
            Cbor::Text(t) => TypedValue::DateTime(DateTime::parse(t).ok_or(ClaimError::Untyped)?),
            _ => return Err(ClaimError::Untyped),
        },
        Cbor::Bool(b) => TypedValue::Bool(*b),
        Cbor::Null => TypedValue::Null,
        Cbor::Tag(..) | Cbor::Encoded(_) => return Err(ClaimError::Untyped),
    })
}
