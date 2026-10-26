//! OpenID4VCI display metadata of one credential configuration, and the merger (D1).

use serde_json::{Map, Value};

use crate::claims::{self, ClaimDescription};
use crate::entry::DisplayEntry;
use crate::error::DisplayError;
use crate::json;
use crate::locale::{Locale, Localized};
use crate::logo;
use crate::text::DisplayText;

/// The Credential Response member that carries delivered secrets (privatedata 3.1, Section
/// 5A.1).
const AUXILIARY_DATA: &str = "auxiliary_data";

/// The display metadata of one credential configuration of a Credential Issuer, as the display
/// cache holds it.
///
/// Its JSON form, which [`IssuerMetadata::to_json`] gives and [`IssuerMetadata::parse`] reads:
///
/// ```json
/// {
///   "credential_issuer": "https://issuer.example",
///   "credential_configuration_id": "pid",
///   "display": [{"name": "Example Issuer", "locale": "en"}],
///   "credential_metadata": {"display": [{"name": "PID", "locale": "en"}], "claims": []}
/// }
/// ```
///
/// `display` is the Credential Issuer's own (OpenID4VCI 1.0, Section 12.2.4). `credential_metadata`
/// is the configuration's, merged with the Credential Response's ([`IssuerMetadata::merge`]); it
/// holds no `auxiliary_data`. Both are optional and keep all their members.
#[derive(Debug, Clone)]
pub struct IssuerMetadata {
    record: Value,
    issuer: String,
    configuration_id: String,
    issuer_display: Vec<IssuerDisplay>,
    display: Vec<DisplayEntry>,
    claims: Vec<ClaimDescription>,
}

/// An issuer `display` entry with a `name`.
#[derive(Debug, Clone)]
pub(crate) struct IssuerDisplay {
    locale: Option<Locale>,
    pub(crate) name: DisplayText,
}

impl Localized for IssuerDisplay {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}

impl IssuerMetadata {
    /// D1: the display metadata of configuration `configuration_id` of the Credential Issuer
    /// Metadata `issuer_metadata`, merged with the `credential_metadata` of a Credential
    /// Response (privatedata 3.1, Section 5A.3).
    ///
    /// `auxiliary_data` leaves the response's object first. Each remaining member then replaces
    /// the configuration's member of the same name. A configuration whose `credential_metadata`
    /// holds `auxiliary_data` is malformed (Section 5A.3).
    ///
    /// # Errors
    ///
    /// [`DisplayError`]: the first rule the inputs or the merged metadata break.
    pub fn merge(
        issuer_metadata: &Value,
        configuration_id: &str,
        response: Option<&Value>,
    ) -> Result<Self, DisplayError> {
        let document = json::object(issuer_metadata)?;
        let issuer = json::string(
            document,
            "credential_issuer",
            DisplayError::IssuerIdentifier,
        )?
        .ok_or(DisplayError::IssuerIdentifier)?;
        let configuration = document
            .get("credential_configurations_supported")
            .and_then(Value::as_object)
            .and_then(|configurations| configurations.get(configuration_id))
            .and_then(Value::as_object)
            .ok_or(DisplayError::ConfigurationUnknown)?;
        let mut merged = match configuration.get("credential_metadata") {
            None => Map::new(),
            Some(metadata) => json::object(metadata)?.clone(),
        };
        if merged.contains_key(AUXILIARY_DATA) {
            return Err(DisplayError::AuxiliaryDataPublished);
        }
        if let Some(response) = response {
            let response = response
                .as_object()
                .ok_or(DisplayError::ResponseMetadataNotObject)?;
            merged.extend(
                response
                    .iter()
                    .filter(|(name, _)| name.as_str() != AUXILIARY_DATA)
                    .map(|(name, value)| (name.clone(), value.clone())),
            );
        }
        let record: Map<String, Value> = [
            Some(("credential_issuer", Value::from(issuer))),
            Some(("credential_configuration_id", configuration_id.into())),
            document
                .get("display")
                .map(|display| ("display", display.clone())),
            Some(("credential_metadata", merged.into())),
        ]
        .into_iter()
        .flatten()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        Self::parse(&record.into())
    }

    /// The display metadata of `record`, the form [`IssuerMetadata::to_json`] gives.
    ///
    /// `display` is a non-empty array of objects, each with an optional string `name` and an
    /// optional `locale`, one per locale. `credential_metadata` is an object without
    /// `auxiliary_data`. Its `display` is a non-empty array of objects with a string `name`, an
    /// optional `locale` (one per locale), `logo`, `background_color` and `text_color`; its
    /// `claims` are claims descriptions (Appendix B.2 and B.3).
    ///
    /// # Errors
    ///
    /// [`DisplayError`]: the first rule `record` breaks.
    pub fn parse(record: &Value) -> Result<Self, DisplayError> {
        let object = json::object(record)?;
        let known = [
            "credential_issuer",
            "credential_configuration_id",
            "display",
            "credential_metadata",
        ];
        if object.keys().any(|name| !known.contains(&name.as_str())) {
            return Err(DisplayError::RecordMemberUnknown);
        }
        let issuer = json::string(object, "credential_issuer", DisplayError::IssuerIdentifier)?
            .ok_or(DisplayError::IssuerIdentifier)?;
        let configuration_id = json::string(
            object,
            "credential_configuration_id",
            DisplayError::ConfigurationId,
        )?
        .ok_or(DisplayError::ConfigurationId)?;
        let empty = Map::new();
        let metadata = match object.get("credential_metadata") {
            None => &empty,
            Some(metadata) => json::object(metadata)?,
        };
        if metadata.contains_key(AUXILIARY_DATA) {
            return Err(DisplayError::AuxiliaryDataPublished);
        }
        let claims = match json::array(metadata, "claims", true, DisplayError::Claims)? {
            None => Vec::new(),
            Some(claims) => claims::issuer_claims(claims)?,
        };
        Ok(Self {
            record: record.clone(),
            issuer: issuer.to_owned(),
            configuration_id: configuration_id.to_owned(),
            issuer_display: issuer_display(object)?,
            display: credential_display(metadata)?,
            claims,
        })
    }

    /// The JSON form, for the display cache.
    pub fn to_json(&self) -> Value {
        self.record.clone()
    }

    /// The Credential Issuer Identifier.
    pub fn credential_issuer(&self) -> &str {
        &self.issuer
    }

    /// The credential configuration identifier.
    pub fn configuration_id(&self) -> &str {
        &self.configuration_id
    }

    /// The issuer `display` entries that have a name.
    pub(crate) fn issuer_display(&self) -> &[IssuerDisplay] {
        &self.issuer_display
    }

    /// The `credential_metadata.display` entries.
    pub(crate) fn display(&self) -> &[DisplayEntry] {
        &self.display
    }

    /// The `credential_metadata.claims` descriptions.
    pub(crate) fn claims(&self) -> &[ClaimDescription] {
        &self.claims
    }
}

/// The issuer `display` entries that have a `name`.
fn issuer_display(object: &Map<String, Value>) -> Result<Vec<IssuerDisplay>, DisplayError> {
    let entries = json::array(object, "display", true, DisplayError::Display)?;
    let mut named = Vec::new();
    let mut locales = Vec::new();
    for entry in entries.unwrap_or_default() {
        let entry = entry.as_object().ok_or(DisplayError::Display)?;
        let locale = json::locale(entry, DisplayError::Display)?;
        locales.push(locale.clone());
        if let Some(name) = json::label(entry, "name", DisplayError::Display)? {
            named.push(IssuerDisplay { locale, name });
        }
    }
    json::distinct_locales(locales.iter().map(Option::as_ref))?;
    Ok(named)
}

/// The `display` entries of `credential_metadata`.
fn credential_display(metadata: &Map<String, Value>) -> Result<Vec<DisplayEntry>, DisplayError> {
    let entries = json::array(metadata, "display", true, DisplayError::Display)?;
    let display = entries
        .unwrap_or_default()
        .iter()
        .map(|entry| {
            let entry = entry.as_object().ok_or(DisplayError::Display)?;
            Ok(DisplayEntry {
                locale: json::locale(entry, DisplayError::Display)?,
                name: json::label(entry, "name", DisplayError::Display)?
                    .ok_or(DisplayError::Display)?,
                logo: logo::optional(entry)?,
                background: json::colour(entry, "background_color")?,
                text: json::colour(entry, "text_color")?,
            })
        })
        .collect::<Result<Vec<_>, DisplayError>>()?;
    json::distinct_locales(display.iter().map(Localized::locale))?;
    Ok(display)
}
