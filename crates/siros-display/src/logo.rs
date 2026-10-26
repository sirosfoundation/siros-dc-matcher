//! Logos of display metadata.

use serde_json::{Map, Value};

use crate::error::DisplayError;
use crate::json;
use crate::text::DisplayText;

/// A logo: where to obtain the image, and its alternative text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Logo {
    uri: String,
    integrity: Option<String>,
    alt_text: Option<DisplayText>,
}

impl Logo {
    /// The logo of a `logo` object: `uri` and `alt_text` (OpenID4VCI 1.0, Section 12.2.4), and
    /// for type metadata `uri#integrity` (SD-JWT VC, Section 5.5.1.1.1).
    ///
    /// `uri` is an `https:` URL or a `data:` URI (SD-JWT VC, Section 5.5.1): the host fetches
    /// HTTPS only.
    pub(crate) fn parse(logo: &Value) -> Result<Self, DisplayError> {
        let logo = logo.as_object().ok_or(DisplayError::Logo)?;
        let uri = match logo.get("uri") {
            Some(Value::String(uri)) if usable(uri) => uri.clone(),
            _ => return Err(DisplayError::Logo),
        };
        let integrity = match logo.get("uri#integrity") {
            None => None,
            Some(Value::String(integrity)) if printable(integrity) => Some(integrity.clone()),
            Some(_) => return Err(DisplayError::Logo),
        };
        Ok(Self {
            uri,
            integrity,
            alt_text: json::label(logo, "alt_text", DisplayError::Logo)?,
        })
    }

    /// The `https:` URL or `data:` URI of the image.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The integrity metadata the fetched image is to match (SD-JWT VC, Section 6). `None`
    /// when the metadata gives none.
    pub fn integrity(&self) -> Option<&str> {
        self.integrity.as_deref()
    }

    /// The alternative text for the image.
    pub fn alt_text(&self) -> Option<&DisplayText> {
        self.alt_text.as_ref()
    }
}

/// `logo`, when `object` has one.
pub(crate) fn optional(object: &Map<String, Value>) -> Result<Option<Logo>, DisplayError> {
    object.get("logo").map(Logo::parse).transpose()
}

/// An `https://` URL with an authority, or a `data:` URI with its comma (RFC 2397), of URI
/// characters only.
fn usable(uri: &str) -> bool {
    let after = |prefix: &str| {
        uri.get(..prefix.len())
            .filter(|scheme| scheme.eq_ignore_ascii_case(prefix))
            .and_then(|_| uri.get(prefix.len()..))
    };
    let https = after("https://").is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
    let data = after("data:").is_some_and(|rest| rest.contains(','));
    (https || data) && uri.bytes().all(|b| b.is_ascii_graphic())
}

/// Visible ASCII characters and spaces.
fn printable(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}
