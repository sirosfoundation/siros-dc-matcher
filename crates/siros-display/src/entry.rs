//! Display entries: how a credential type shows in one locale.

use crate::colour::Colour;
use crate::locale::{Locale, Localized};
use crate::logo::Logo;
use crate::text::DisplayText;

/// A `display` entry of OpenID4VCI `credential_metadata` (OpenID4VCI 1.0, Section 12.2.4) or of
/// Type Metadata with its `simple` rendering (SD-JWT VC, Sections 5.5 and 5.5.1.1).
#[derive(Debug, Clone)]
pub(crate) struct DisplayEntry {
    pub(crate) locale: Option<Locale>,
    pub(crate) name: DisplayText,
    pub(crate) logo: Option<Logo>,
    pub(crate) background: Option<Colour>,
    pub(crate) text: Option<Colour>,
}

impl Localized for DisplayEntry {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}
