//! Claims path pointer resolution (C3): Q4 for SD-JWT VC, `[namespace, element]` for mdoc
//! (OpenID4VP 1.0, Sections 7.1 and 7.2).

use serde_json::{Map, Value as Json};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_dcql::{mdoc_components, resolve, PathComponent, PathError};
use siros_mdoc::{IssuerSignedItem, Mdoc};
use siros_sdjwt::{ClaimValue, Element, Node, NodeValue};

use crate::credential::{Body, Credential};
use crate::error::ClaimError;
use crate::pointer::ClaimPointer;
use crate::usable::UsableCredential;
use crate::value::{self, TypedValue};

/// A claim a pointer selects, in its format's tree.
enum Found<'a> {
    SdJwt(Node<'a>),
    Mdoc(&'a Cbor),
}

impl Credential {
    /// The values of the claims `pointer` selects, in the order of their selection.
    ///
    /// For an SD-JWT VC, [`siros_dcql::resolve`] walks the claim tree: an index counts issued
    /// positions and selects nothing at a withheld one, and `null` selects the present
    /// elements. For an mdoc, the pointer is `[namespace, element]` and selects that element's
    /// value.
    ///
    /// # Errors
    ///
    /// [`ClaimError::Path`] when the pointer does not fit the credential or selects nothing;
    /// [`ClaimError::Untyped`] when a selected value has none of the ten types.
    pub fn claims(&self, pointer: &ClaimPointer) -> Result<Vec<TypedValue<'_>>, ClaimError> {
        self.select(pointer.components())?
            .into_iter()
            .map(|found| match found {
                Found::SdJwt(node) => match node.value() {
                    NodeValue::Payload(object) => Ok(value::payload(object)),
                    NodeValue::Claim(claim) => value::json(claim.value()),
                },
                Found::Mdoc(value) => value::cbor(value),
            })
            .collect()
    }

    fn select(&self, path: &[PathComponent]) -> Result<Vec<Found<'_>>, PathError> {
        match &self.body {
            Body::SdJwtVc(vc) => Ok(resolve(vc.sd_jwt().root(), path)?
                .into_iter()
                .map(Found::SdJwt)
                .collect()),
            Body::Mdoc(mdoc) => Ok(vec![Found::Mdoc(element(mdoc, path)?)]),
        }
    }
}

/// The value of the element `path` names (Section 7.2.1). A namespace or an element the mdoc
/// lacks selects nothing.
fn element<'a>(mdoc: &'a Mdoc, path: &[PathComponent]) -> Result<&'a Cbor, PathError> {
    let (name_space, identifier) = mdoc_components(path)?;
    mdoc.name_spaces()
        .iter()
        .find(|n| n.name() == name_space)
        .and_then(|n| n.items().iter().find(|i| i.identifier() == identifier))
        .map(IssuerSignedItem::value)
        .ok_or(PathError::Empty)
}

/// DCQL evaluation (OpenID4VP 1.0, Section 6.4) over the credential.
///
/// [`claim`](siros_dcql::Credential::claim) gives each selected value as JSON for the
/// comparison with `values` (Section 6.3). An mdoc value converts as RFC 8949, Section 6.1
/// converts CBOR to JSON: a tag gives its content, so a `full-date` compares as
/// `"YYYY-MM-DD"`; a byte string gives its base64url text; `undefined` gives `null`; a map key
/// other than text gives the JSON text of its conversion.
impl siros_dcql::Credential for Credential {
    /// The decimal `credentialId`.
    fn id(&self) -> &str {
        Credential::id(self)
    }

    /// `dc+sd-jwt` or `mso_mdoc`.
    fn format(&self) -> &str {
        Credential::format(self).identifier()
    }

    fn claim(&self, path: &[PathComponent]) -> Result<Vec<Json>, PathError> {
        Ok(self
            .select(path)?
            .into_iter()
            .map(|found| match found {
                Found::SdJwt(node) => match node.value() {
                    NodeValue::Payload(object) => sd_jwt_object(object),
                    NodeValue::Claim(claim) => sd_jwt_json(claim.value()),
                },
                Found::Mdoc(value) => cbor_json(value),
            })
            .collect())
    }

    /// An SD-JWT VC is bound when it has `cnf`; an mdoc always has its MSO's device key.
    fn has_cryptographic_holder_binding(&self) -> bool {
        match &self.body {
            Body::SdJwtVc(vc) => vc.bound(),
            Body::Mdoc(_) => true,
        }
    }
}

/// DCQL evaluation over usable credentials only (A1).
impl siros_dcql::Credential for UsableCredential<'_> {
    fn id(&self) -> &str {
        siros_dcql::Credential::id(self.credential())
    }

    fn format(&self) -> &str {
        siros_dcql::Credential::format(self.credential())
    }

    fn claim(&self, path: &[PathComponent]) -> Result<Vec<Json>, PathError> {
        self.credential().claim(path)
    }

    fn has_cryptographic_holder_binding(&self) -> bool {
        self.credential().has_cryptographic_holder_binding()
    }
}

fn sd_jwt_object(object: &siros_sdjwt::Object) -> Json {
    Json::Object(
        object
            .members()
            .map(|(name, claim)| (name.to_owned(), sd_jwt_json(claim.value())))
            .collect::<Map<String, Json>>(),
    )
}

/// The present claims of `value` as JSON.
fn sd_jwt_json(value: &ClaimValue) -> Json {
    match value {
        ClaimValue::Null => Json::Null,
        ClaimValue::Bool(b) => Json::Bool(*b),
        ClaimValue::Number(n) => Json::Number(n.clone()),
        ClaimValue::String(s) => Json::String(s.clone()),
        ClaimValue::Array(elements) => Json::Array(
            elements
                .iter()
                .filter_map(|element| match element {
                    Element::Present(claim) => Some(sd_jwt_json(claim.value())),
                    Element::Withheld => None,
                })
                .collect(),
        ),
        ClaimValue::Object(object) => sd_jwt_object(object),
    }
}

/// `value` as JSON (RFC 8949, Section 6.1).
fn cbor_json(value: &Cbor) -> Json {
    match value {
        Cbor::Unsigned(n) => Json::from(*n),
        // Below -2^63 JSON holds the integer as a float only.
        Cbor::Negative(n) => {
            i64::try_from(*n).map_or(Json::from(-1.0 - *n as f64), |n| Json::from(-1 - n))
        }
        Cbor::Bytes(b) => Json::String(base64url::encode(b)),
        Cbor::Text(t) => Json::String(t.clone()),
        Cbor::Array(items) => Json::Array(items.iter().map(cbor_json).collect()),
        Cbor::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    let key = match key {
                        Cbor::Text(t) => t.clone(),
                        other => cbor_json(other).to_string(),
                    };
                    (key, cbor_json(value))
                })
                .collect::<Map<String, Json>>(),
        ),
        Cbor::Tag(_, inner) => cbor_json(inner),
        Cbor::Bool(b) => Json::Bool(*b),
        Cbor::Null | Cbor::Encoded(_) => Json::Null,
    }
}
