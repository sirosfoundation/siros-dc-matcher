//! Credential cards (D2, D3).

use siros_credential::{Credential, Format};

use crate::cache::DisplayCache;
use crate::colour::Colour;
use crate::error::DisplayError;
use crate::issuer::IssuerMetadata;
use crate::locale::{choose, Locale};
use crate::logo::Logo;
use crate::text::DisplayText;
use crate::type_metadata::TypeMetadata;

/// What shows a credential to the user: its title, its issuer, its logo and its colours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Card {
    title: DisplayText,
    issuer: Option<DisplayText>,
    logo: Option<Logo>,
    background: Option<Colour>,
    text: Option<Colour>,
}

impl Card {
    /// The title.
    pub fn title(&self) -> &DisplayText {
        &self.title
    }

    /// The issuer line.
    pub fn issuer(&self) -> Option<&DisplayText> {
        self.issuer.as_ref()
    }

    /// The logo.
    pub fn logo(&self) -> Option<&Logo> {
        self.logo.as_ref()
    }

    /// The background colour.
    pub fn background(&self) -> Option<Colour> {
        self.background
    }

    /// The text colour.
    pub fn text(&self) -> Option<Colour> {
        self.text
    }
}

impl DisplayCache {
    /// The card of `credential` for the user's `preferences`, most preferred first.
    ///
    /// [`choose`] takes the entry from the `display` of the credential's Type Metadata, the
    /// nearest type that has one (SD-JWT VC, Section 5.5.2). Without a type entry it takes it from
    /// the `credential_metadata.display` of the credential's configuration, the fallback (D3,
    /// OpenID4VCI 1.0, Section 12.2.4). The entry gives the title, logo and colours; without any
    /// entry the title is the credential type. The issuer line is the
    /// chosen named entry of the Credential Issuer's `display`, else the credential's Credential
    /// Issuer Identifier.
    ///
    /// # Errors
    ///
    /// [`DisplayError::Text`] when the title or the issuer line falls back to an identifier
    /// that is no safe label.
    pub fn card(
        &self,
        credential: &Credential,
        preferences: &[Locale],
    ) -> Result<Card, DisplayError> {
        let issued = self.issued(credential);
        let type_display = self
            .types_of(credential)
            .into_iter()
            .find_map(TypeMetadata::display)
            .unwrap_or_default();
        let entries = match type_display {
            [] => issued.map(IssuerMetadata::display).unwrap_or_default(),
            typed => typed,
        };
        let issuer = match issued.and_then(|m| choose(preferences, m.issuer_display())) {
            Some(named) => Some(named.text.clone()),
            None => credential
                .issuer()
                .map(DisplayText::label)
                .transpose()
                .map_err(DisplayError::Text)?,
        };
        Ok(match choose(preferences, entries) {
            Some(entry) => Card {
                title: entry.name.clone(),
                issuer,
                logo: entry.logo.clone(),
                background: entry.background,
                text: entry.text,
            },
            None => Card {
                title: DisplayText::label(credential.credential_type())
                    .map_err(DisplayError::Text)?,
                issuer,
                logo: None,
                background: None,
                text: None,
            },
        })
    }

    /// The OpenID4VCI display metadata of `credential`'s configuration.
    pub(crate) fn issued(&self, credential: &Credential) -> Option<&IssuerMetadata> {
        let issuer = credential.issuer()?;
        self.issuer(issuer, credential.configuration_id()?)
    }

    /// The Type Metadata of an SD-JWT VC's `vct` and of the types it extends.
    pub(crate) fn types_of(&self, credential: &Credential) -> Vec<&TypeMetadata> {
        match credential.format() {
            Format::SdJwtVc => self.type_chain(credential.credential_type()).collect(),
            Format::Mdoc => Vec::new(),
        }
    }
}
