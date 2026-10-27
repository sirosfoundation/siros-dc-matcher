//! The SD-JWT VC Type Metadata of an SCA Attestation (EC TS12 v1.0.1, Sections 3 and 4.1): the
//! document at the credential's `vct` and the documents it references, each a host fetch (T7,
//! H1), read into definitions.

use std::str::Utf8Error;

use siros_codec::json::{Json, JsonFault};
use siros_codec::member::MemberFault;
use siros_credential::{Credential, Format, TypedValue};
use siros_dcql::{ClaimPath, PathError};
use siros_oid4vp::{BodyLimit, HttpsUrl, MediaType};

use super::ts12_map;
use crate::definition::{Definition, DefinitionError};
use crate::fetched::{FetchFault, Fetched, Step};
use crate::integrity::{Integrity, IntegrityFault};
use crate::json::{self, Fields};
use crate::type_id::{Ts12Type, TypeId};

/// The largest metadata document read.
const MAX_DOCUMENT: BodyLimit = BodyLimit::bytes(256 * 1024);

/// The `category` of an SCA Attestation (Section 3).
const SCA_CATEGORY: &str = "urn:eu:europa:ec:eudi:sua:sca";

/// A member of TS12 type metadata, of a `transaction_data_types` entry, or of its documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ts12Member {
    /// `vct`.
    Vct,
    /// `category`.
    Category,
    /// `transaction_data_types`.
    TransactionDataTypes,
    /// A `transaction_data_types` entry.
    Entry,
    /// `schema` or `schema_uri`.
    Schema,
    /// `claims` or `claims_uri`.
    Claims,
    /// `ui_labels` or `ui_labels_uri`.
    UiLabels,
    /// A claim's `path`.
    Path,
    /// A claim's `visualisation`.
    Visualisation,
    /// A claim's `display`.
    Display,
    /// A display entry's `lang` or `locale`.
    Lang,
    /// A display entry's `label`.
    Label,
    /// A UI elements catalogue entry.
    UiEntry,
}

/// Why TS12 type metadata gives no definition of a type (Sections 3.2, 3.3 and 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ts12Fault {
    /// The credential's `vct#integrity` or a `transaction_data_types[…]#integrity` claim is no
    /// integrity metadata this wallet reads (SD-JWT VC, Section 7).
    Pin(IntegrityFault),
    /// A fetch gave no document.
    Fetch(FetchFault),
    /// A document's bytes are no UTF-8 text.
    NotUtf8(Utf8Error),
    /// A document's text is no JSON document the strict reader holds.
    NotJson(JsonFault),
    /// A document does not match its `#integrity` claim (SD-JWT VC, Section 7).
    Integrity(IntegrityFault),
    /// A member breaks its rule.
    Member(Ts12Member, MemberFault),
    /// The document describes another `vct` than the credential's (SD-JWT VC, Section 6.3).
    VctMismatch,
    /// An entry gives both or neither of a member and its `_uri` form (Section 4.1).
    OneOf(Ts12Member),
    /// A referenced document's URL is no `https` URL.
    DocumentNotHttps(String),
    /// `schema` is an embedded JSON Schema, which the wallet does not validate payloads
    /// against.
    SchemaEmbedded,
    /// `schema` names no schema of Section 4.3.
    SchemaUnknown(String),
    /// `schema` names another type's schema than the entry's built-in type.
    SchemaMismatch(Ts12Type),
    /// A claim's `path` is not rooted at `payload` (Section 2.3).
    PathOutsidePayload,
    /// A `visualisation` is no integer from 1 to 4 (Section 3.3.2).
    Visualisation,
    /// A UI element's value is longer than Section 3.3.3 allows: the element and the length.
    LabelLength(&'static str, usize),
    /// The catalogue has no `affirmative_action_label` (Section 3.3.3).
    AffirmativeAbsent,
    /// The mapped definition breaks PaSO Proof Metadata, Section 3.
    Definition(DefinitionError),
}

impl Ts12Fault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Pin(_) => "type_metadata_pin_malformed",
            Self::Fetch(fault) => fault.code(),
            Self::NotUtf8(_) | Self::NotJson(_) | Self::Member(..) | Self::OneOf(_) => {
                "type_metadata_malformed"
            }
            Self::Integrity(fault) => fault.code(),
            Self::VctMismatch => "type_metadata_vct_mismatch",
            Self::DocumentNotHttps(_) => "type_metadata_document_not_https",
            Self::SchemaEmbedded => "type_metadata_schema_embedded",
            Self::SchemaUnknown(_) => "type_metadata_schema_unknown",
            Self::SchemaMismatch(_) => "type_metadata_schema_mismatch",
            Self::PathOutsidePayload => "type_metadata_path_outside_payload",
            Self::Visualisation => "type_metadata_visualisation",
            Self::LabelLength(..) => "type_metadata_label_length",
            Self::AffirmativeAbsent => "type_metadata_affirmative_absent",
            Self::Definition(error) => error.code(),
        }
    }
}

siros_codec::display_code!(Ts12Fault);

impl std::error::Error for Ts12Fault {}

/// The type metadata of an SCA Attestation: its `transaction_data_types` entries. A credential
/// of another category has none (Section 3.2, step 1).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TypeMetadata(Vec<(String, Json)>);

/// A document held inline, or referenced by URL with the credential's pin.
enum Document {
    Inline(Json),
    Referenced(HttpsUrl, Option<Integrity>),
}

impl TypeMetadata {
    /// The type metadata of `credential`, an SD-JWT VC: the document at its `vct` (SD-JWT VC,
    /// Section 6.3.1); the fetch while the host has not given it. A `vct` that is no `https` URL
    /// locates no document, and a document the host does not find is none, unless
    /// `vct#integrity` pins one.
    pub(crate) fn load(
        credential: &Credential,
        fetched: &Fetched,
    ) -> Result<Step<Option<Self>>, Ts12Fault> {
        if credential.format() != Format::SdJwtVc {
            return Ok(Step::Done(None));
        }
        let Some(url) = HttpsUrl::parse(credential.credential_type().as_str()) else {
            return Ok(Step::Done(None));
        };
        let pin = pin(credential, "vct#integrity")?;
        let body = match fetched.body(&url, MediaType::JSON, MAX_DOCUMENT) {
            Ok(Step::Fetch(fetch)) => return Ok(Step::Fetch(fetch)),
            Ok(Step::Done(body)) => body,
            Err(FetchFault::Status(_)) if pin.is_none() => return Ok(Step::Done(None)),
            Err(fault) => return Err(Ts12Fault::Fetch(fault)),
        };
        let mut fields = json::object(document_of(body, pin.as_ref())?)
            .map_err(|fault| Ts12Fault::Member(Ts12Member::Vct, fault))?;
        match fields.require("vct").and_then(json::text) {
            Ok(vct) if vct == credential.credential_type().as_str() => {}
            Ok(_) => return Err(Ts12Fault::VctMismatch),
            Err(fault) => return Err(Ts12Fault::Member(Ts12Member::Vct, fault)),
        }
        let category = fields
            .optional("category", json::text)
            .map_err(|fault| Ts12Fault::Member(Ts12Member::Category, fault))?;
        let types = fields
            .optional("transaction_data_types", json::object)
            .map_err(|fault| Ts12Fault::Member(Ts12Member::TransactionDataTypes, fault))?;
        let entries = match (category.as_deref(), types) {
            (Some(SCA_CATEGORY), Some(types)) => types.rest(),
            _ => Vec::new(),
        };
        Ok(Step::Done(Some(Self(entries))))
    }

    /// The definition of `type_id` and the built-in schema its payloads follow, when the
    /// metadata lists the type; the fetch of a referenced document while the host has not
    /// given it.
    pub(crate) fn definition(
        &self,
        type_id: &TypeId,
        credential: &Credential,
        fetched: &Fetched,
    ) -> Option<Result<Step<(Definition, Ts12Type)>, Ts12Fault>> {
        let (_, entry) = self.0.iter().find(|(name, _)| name == type_id.as_str())?;
        Some(entry_definition(
            type_id,
            entry.clone(),
            credential,
            fetched,
        ))
    }
}

/// The definition of the `transaction_data_types` entry `entry` of `type_id`.
fn entry_definition(
    type_id: &TypeId,
    entry: Json,
    credential: &Credential,
    fetched: &Fetched,
) -> Result<Step<(Definition, Ts12Type)>, Ts12Fault> {
    let mut fields =
        json::object(entry).map_err(|fault| Ts12Fault::Member(Ts12Member::Entry, fault))?;
    let schema = schema(type_id, &mut fields)?;
    let claims = source(
        type_id,
        &mut fields,
        "claims",
        Ts12Member::Claims,
        credential,
    )?;
    let labels = source(
        type_id,
        &mut fields,
        "ui_labels",
        Ts12Member::UiLabels,
        credential,
    )?;
    let claims = match resolve(claims, fetched)? {
        Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
        Step::Done(claims) => claims,
    };
    let labels = match resolve(labels, fetched)? {
        Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
        Step::Done(labels) => labels,
    };
    let definition = ts12_map::definition(claims, labels)?;
    Ok(Step::Done((definition, schema)))
}

/// The built-in schema `schema` or `schema_uri` names (Sections 3.2 and 4.1), one of the two:
/// the payload rulebook of the type. It agrees with the built-in type of `type_id`.
fn schema(type_id: &TypeId, fields: &mut Fields) -> Result<Ts12Type, Ts12Fault> {
    let named = match (fields.take("schema"), fields.take("schema_uri")) {
        (Some(Json::String(name)), None) | (None, Some(Json::String(name))) => name,
        (Some(Json::Object(_)), None) => return Err(Ts12Fault::SchemaEmbedded),
        (Some(_), None) | (None, Some(_)) => {
            return Err(Ts12Fault::Member(
                Ts12Member::Schema,
                MemberFault::WrongType,
            ))
        }
        (Some(_), Some(_)) | (None, None) => return Err(Ts12Fault::OneOf(Ts12Member::Schema)),
    };
    let schema = Ts12Type::schema(&named).ok_or(Ts12Fault::SchemaUnknown(named))?;
    match type_id.rulebook() {
        Some(builtin) if builtin != schema => Err(Ts12Fault::SchemaMismatch(builtin)),
        Some(_) | None => Ok(schema),
    }
}

/// The document of member `name` of the entry of `type_id`: inline in `name`, or referenced by
/// `<name>_uri`, exactly one of them. The credential's
/// `transaction_data_types['<type>'].<name>_uri#integrity` claim pins a referenced document
/// (Section 4.1.2).
fn source(
    type_id: &TypeId,
    fields: &mut Fields,
    name: &str,
    member: Ts12Member,
    credential: &Credential,
) -> Result<Document, Ts12Fault> {
    let uri = format!("{name}_uri");
    match (fields.take(name), fields.take(&uri)) {
        (Some(inline), None) => Ok(Document::Inline(inline)),
        (None, Some(Json::String(url))) => {
            let pinned = format!("transaction_data_types['{type_id}'].{uri}#integrity");
            Ok(Document::Referenced(
                HttpsUrl::parse(&url).ok_or(Ts12Fault::DocumentNotHttps(url))?,
                pin(credential, &pinned)?,
            ))
        }
        (None, Some(_)) => Err(Ts12Fault::Member(member, MemberFault::WrongType)),
        (Some(_), Some(_)) | (None, None) => Err(Ts12Fault::OneOf(member)),
    }
}

/// The JSON value of `document`; the fetch of a referenced one while the host has not given
/// it.
fn resolve(document: Document, fetched: &Fetched) -> Result<Step<Json>, Ts12Fault> {
    match document {
        Document::Inline(value) => Ok(Step::Done(value)),
        Document::Referenced(url, pin) => {
            match fetched
                .body(&url, MediaType::JSON, MAX_DOCUMENT)
                .map_err(Ts12Fault::Fetch)?
            {
                Step::Fetch(fetch) => Ok(Step::Fetch(fetch)),
                Step::Done(body) => document_of(body, pin.as_ref()).map(Step::Done),
            }
        }
    }
}

/// The JSON document `body` holds, checked against `pin` when the credential pins it.
fn document_of(body: &[u8], pin: Option<&Integrity>) -> Result<Json, Ts12Fault> {
    if let Some(pin) = pin {
        pin.check(body).map_err(Ts12Fault::Integrity)?;
    }
    let text = std::str::from_utf8(body).map_err(Ts12Fault::NotUtf8)?;
    Json::parse_unique(text.as_bytes()).map_err(Ts12Fault::NotJson)
}

/// The integrity metadata of the credential's top-level claim `name`, when it has the claim.
fn pin(credential: &Credential, name: &str) -> Result<Option<Integrity>, Ts12Fault> {
    match credential.claims(&ClaimPath::key(name)).as_deref() {
        Err(PathError::Empty) => Ok(None),
        Ok([TypedValue::Text(text)]) => Integrity::parse(text).map(Some).map_err(Ts12Fault::Pin),
        Ok(_) | Err(_) => Err(Ts12Fault::Pin(IntegrityFault::Malformed)),
    }
}
