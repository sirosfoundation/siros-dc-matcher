//! The type metadata of an SD-JWT VC and the documents it references, each fetched by the host
//! (T7, H1).

use std::collections::hash_map::Entry;

use rustc_hash::FxHashMap;
use siros_credential::{ClaimPointer, Credential, Format, TypedValue};
use siros_dcql::{PathComponent, PathError};
use siros_oid4vp::{Fetch, FetchResponse, HttpsUrl};

use crate::error::TransactionDataError;
use crate::integrity::Integrity;
use crate::json::{Fields, Json};
use crate::kind;
use crate::labels::{ClaimMetadata, DisplayMetadata, UiLabels};

/// The largest metadata document read, in bytes.
const MAX_DOCUMENT: usize = 256 * 1024;

/// The media type a metadata fetch accepts.
const JSON: &str = "application/json";

/// The SCA Attestation metadata of a credential: the `category` and `transaction_data_types`
/// of its SD-JWT VC Type Metadata (SD-JWT VC, Section 6; EC TS12 v1.0.1, Sections 2.3 and 4.1).
pub struct ScaMetadata<'c> {
    credential: &'c Credential,
    category: Option<String>,
    types: Vec<(&'static str, TypeDisplay)>,
}

/// Where the display metadata of one transaction data type is: inline or referenced
/// (EC TS12 v1.0.1, Section 4.1).
pub(crate) struct TypeDisplay {
    claims: Source<ClaimMetadata>,
    ui_labels: Source<UiLabels>,
}

/// A document held inline, or referenced by URL.
enum Source<T> {
    Inline(T),
    Referenced(Reference),
}

/// A referenced document, with the `#integrity` claim of the credential that pins it.
struct Reference {
    url: HttpsUrl,
    integrity: Option<Integrity>,
}

/// The responses the host gave to the fetches of transaction data, by URL.
#[derive(Default)]
pub struct Fetched(FxHashMap<HttpsUrl, FetchResponse>);

/// What a step of transaction data gives: a fetch for the host, or the value.
pub enum Step<T> {
    /// The document to fetch. Its response goes to [`Fetched::insert_first`], and the step is
    /// taken again.
    Fetch(Fetch),
    /// The value.
    Done(T),
}

impl Fetched {
    /// No response yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `response`, the host's first response to `fetch`, and gives it as recorded.
    ///
    /// # Errors
    ///
    /// `response`, back, when a response for the URL is recorded already.
    pub fn insert_first(
        &mut self,
        fetch: &Fetch,
        response: FetchResponse,
    ) -> Result<&FetchResponse, FetchResponse> {
        match self.0.entry(fetch.url().clone()) {
            Entry::Occupied(_) => Err(response),
            Entry::Vacant(vacant) => Ok(vacant.insert(response)),
        }
    }

    /// The response recorded for the URL of `fetch`.
    #[must_use]
    pub fn response(&self, fetch: &Fetch) -> Option<&FetchResponse> {
        self.0.get(fetch.url())
    }
}

impl<'c> ScaMetadata<'c> {
    /// The fetch of the type metadata of `credential`: a `GET` of its `vct` (SD-JWT VC, Section
    /// 6.3.1; EC TS12 v1.0.1, Section 4.1.1).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::NotSdJwtVc`] for another format,
    /// [`TransactionDataError::VctNotHttps`] for a `vct` that is no `https` URL.
    pub fn fetch(credential: &Credential) -> Result<Fetch, TransactionDataError> {
        if credential.format() != Format::SdJwtVc {
            return Err(TransactionDataError::NotSdJwtVc);
        }
        let url = HttpsUrl::parse(credential.credential_type())
            .ok_or(TransactionDataError::VctNotHttps)?;
        Ok(Fetch::get(url, JSON, MAX_DOCUMENT))
    }

    /// The SCA Attestation metadata of `credential` in `response`, the response to
    /// [`ScaMetadata::fetch`].
    ///
    /// The document matches the credential's `vct#integrity` when it has one (Section 7), and
    /// its `vct` is the credential's (Section 6.3). Of `transaction_data_types`, the entries of
    /// the supported types are read; each gives `claims` or `claims_uri`, and `ui_labels` or
    /// `ui_labels_uri`, exactly one of each pair. The credential's
    /// `transaction_data_types['<type>'].<member>#integrity` claim pins a referenced document
    /// (EC TS12 v1.0.1, Section 4.1.2).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: the first rule the response or the document breaks.
    pub fn parse(
        credential: &'c Credential,
        response: &FetchResponse,
    ) -> Result<Self, TransactionDataError> {
        if credential.format() != Format::SdJwtVc {
            return Err(TransactionDataError::NotSdJwtVc);
        }
        let document = read(response, pin(credential, "vct#integrity")?.as_ref())?;
        let Json::Object(object) = document else {
            return Err(TransactionDataError::MetadataMalformed("type metadata"));
        };
        let mut fields = object.into_fields();
        match fields.take("vct") {
            Some(Json::String(vct)) if vct == credential.credential_type() => {}
            Some(Json::String(_)) => return Err(TransactionDataError::VctMismatch),
            _ => return Err(TransactionDataError::MetadataMalformed("vct")),
        }
        let category = match fields.take("category") {
            None => None,
            Some(Json::String(category)) => Some(category),
            Some(_) => return Err(TransactionDataError::MetadataMalformed("category")),
        };
        let types = match fields.take("transaction_data_types") {
            None => Vec::new(),
            Some(Json::Object(types)) => transaction_data_types(credential, types.into_fields())?,
            Some(_) => {
                return Err(TransactionDataError::MetadataMalformed(
                    "transaction_data_types",
                ))
            }
        };
        Ok(Self {
            credential,
            category,
            types,
        })
    }

    /// The credential.
    #[must_use]
    pub fn credential(&self) -> &'c Credential {
        self.credential
    }

    /// `category`.
    pub(crate) fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Where the display metadata of the type `identifier` is, when `transaction_data_types`
    /// lists it.
    pub(crate) fn display_metadata(&self, identifier: &str) -> Option<&TypeDisplay> {
        self.types
            .iter()
            .find(|(listed, _)| *listed == identifier)
            .map(|(_, display)| display)
    }
}

/// The entries of `types` for the supported types.
fn transaction_data_types(
    credential: &Credential,
    types: Fields,
) -> Result<Vec<(&'static str, TypeDisplay)>, TransactionDataError> {
    const PATH: &str = "transaction_data_types";
    let mut supported = Vec::new();
    for (name, value) in types.rest() {
        let Some(identifier) = kind::supported(&name) else {
            continue;
        };
        let Json::Object(entry) = value else {
            return Err(TransactionDataError::MetadataMalformed(PATH));
        };
        let mut entry = entry.into_fields();
        let display = TypeDisplay {
            claims: source(
                credential,
                identifier,
                &mut entry,
                "claims",
                ClaimMetadata::parse,
            )?,
            ui_labels: source(
                credential,
                identifier,
                &mut entry,
                "ui_labels",
                UiLabels::parse,
            )?,
        };
        supported.push((identifier, display));
    }
    Ok(supported)
}

/// The document of member `name` of the entry of type `identifier`: inline in `name`, or
/// referenced by `<name>_uri`, exactly one of them.
fn source<T>(
    credential: &Credential,
    identifier: &str,
    entry: &mut Fields,
    name: &'static str,
    parse: fn(Json) -> Result<T, TransactionDataError>,
) -> Result<Source<T>, TransactionDataError> {
    let uri = format!("{name}_uri");
    match (entry.take(name), entry.take(&uri)) {
        (Some(inline), None) => Ok(Source::Inline(parse(inline)?)),
        (None, Some(Json::String(url))) => Ok(Source::Referenced(Reference {
            url: HttpsUrl::parse(&url).ok_or(TransactionDataError::DocumentNotHttps)?,
            integrity: pin(
                credential,
                &format!("transaction_data_types['{identifier}'].{uri}#integrity"),
            )?,
        })),
        _ => Err(TransactionDataError::MetadataMalformed(name)),
    }
}

impl TypeDisplay {
    /// The display metadata, its referenced documents read from `fetched`.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: the first rule a fetched document breaks.
    pub(crate) fn resolve(
        &self,
        fetched: &Fetched,
    ) -> Result<Step<DisplayMetadata>, TransactionDataError> {
        let claims = match resolve(&self.claims, fetched, ClaimMetadata::parse)? {
            Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
            Step::Done(claims) => claims,
        };
        let ui_labels = match resolve(&self.ui_labels, fetched, UiLabels::parse)? {
            Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
            Step::Done(ui_labels) => ui_labels,
        };
        Ok(Step::Done(DisplayMetadata { claims, ui_labels }))
    }
}

/// The document of `source`.
fn resolve<T: Clone>(
    source: &Source<T>,
    fetched: &Fetched,
    parse: fn(Json) -> Result<T, TransactionDataError>,
) -> Result<Step<T>, TransactionDataError> {
    match source {
        Source::Inline(document) => Ok(Step::Done(document.clone())),
        Source::Referenced(reference) => match fetched.0.get(&reference.url) {
            None => Ok(Step::Fetch(Fetch::get(
                reference.url.clone(),
                JSON,
                MAX_DOCUMENT,
            ))),
            Some(response) => Ok(Step::Done(parse(read(
                response,
                reference.integrity.as_ref(),
            )?)?)),
        },
    }
}

/// The JSON document `response` holds, checked against `integrity` when it is pinned.
fn read(
    response: &FetchResponse,
    integrity: Option<&Integrity>,
) -> Result<Json, TransactionDataError> {
    if response.status() != 200 {
        return Err(TransactionDataError::FetchStatus);
    }
    let body = response.body();
    if body.len() > MAX_DOCUMENT {
        return Err(TransactionDataError::FetchTooLarge);
    }
    if let Some(integrity) = integrity {
        integrity.check(body)?;
    }
    let malformed = TransactionDataError::MetadataMalformed("document");
    let text = std::str::from_utf8(body).map_err(|_| malformed)?;
    Json::parse(text).map_err(|_| malformed)
}

/// The integrity metadata of the credential's top-level claim `name`, when it has the claim.
fn pin(credential: &Credential, name: &str) -> Result<Option<Integrity>, TransactionDataError> {
    let pointer = ClaimPointer::parse(vec![PathComponent::Key(name.to_owned())])
        .map_err(|_| TransactionDataError::IntegrityMalformed)?;
    match credential.claims(&pointer).as_deref() {
        Err(PathError::Empty) => Ok(None),
        Ok([TypedValue::Text(text)]) => Integrity::parse(text).map(Some),
        _ => Err(TransactionDataError::IntegrityMalformed),
    }
}
