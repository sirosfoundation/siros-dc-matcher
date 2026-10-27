//! The sources of one credential: its own metadata, loaded and verified once, and the entry by
//! entry precedence of the sources.

use siros_credential::{Credential, Format};
use siros_display::{DisplayCache, Locale};

use super::config::Configuration;
use super::paso::CredentialMetadata;
use super::signed::Verifier;
use super::ts12::{Ts12Fault, TypeMetadata};
use super::{Rulebook, SourceKind};
use crate::definition::{Definition, DefinitionError};
use crate::entry::Entry;
use crate::projection::Projected;
use crate::select::{Definitions, Incompatibility};
use crate::type_id::TypeId;

/// The sources of one credential, its own metadata loaded.
pub(crate) struct CredentialSources<'c> {
    credential: &'c Credential,
    verifier: Verifier<'c>,
    configuration: &'c Configuration,
    language: &'c Locale,
    /// The credential's signed credential metadata, verified, when it is a PaSO Credential.
    paso: Option<CredentialMetadata>,
    /// The credential's SCA type metadata, or why it does not read.
    ts12: Result<Option<TypeMetadata>, Ts12Fault>,
}

impl<'c> CredentialSources<'c> {
    /// The sources of `credential`, read in `language`. A credential whose configuration names
    /// a `credential_metadata_uri` in the issuer metadata `display` holds is a PaSO Credential:
    /// the host holds its signed credential metadata (PaSO Proof Metadata, Section 3).
    ///
    /// # Errors
    ///
    /// The credential takes no entry: [`Incompatibility::Format`] for a credential other than an
    /// SD-JWT VC, [`Incompatibility::IssuerMetadataNotHeld`] when the host holds no issuer
    /// metadata of its configuration, and [`Incompatibility::CredentialMetadata`] for signed
    /// credential metadata that is not held or not valid (Sections 3, 6 and 7).
    pub(crate) fn load(
        credential: &'c Credential,
        verifier: Verifier<'c>,
        display: &DisplayCache,
        configuration: &'c Configuration,
        language: &'c Locale,
    ) -> Result<Self, Incompatibility> {
        if credential.format() != Format::SdJwtVc {
            return Err(Incompatibility::Format);
        }
        let issued = display
            .issuer_metadata(credential)
            .ok_or(Incompatibility::IssuerMetadataNotHeld)?;
        let paso = issued
            .credential_metadata_uri()
            .map(|_| CredentialMetadata::load(credential, verifier))
            .transpose()
            .map_err(Incompatibility::CredentialMetadata)?;
        Ok(Self {
            credential,
            verifier,
            configuration,
            language,
            paso,
            ts12: TypeMetadata::load(credential, verifier.held),
        })
    }

    /// The definition of `type_id` the credential's own metadata gives; for a credential
    /// without metadata of its own, the one the configuration gives. Signed credential metadata
    /// comes before SCA type metadata.
    ///
    /// # Errors
    ///
    /// [`Incompatibility`]: why no source serves the type.
    pub(crate) fn served(&self, type_id: &TypeId) -> Result<Projected, Incompatibility> {
        let rulebook = Rulebook::of_type(type_id);
        if let Some(definition) = self.paso.as_ref().and_then(|paso| paso.definition(type_id)) {
            return self.project(definition.clone(), SourceKind::CredentialMetadata, rulebook);
        }
        let ts12 = self
            .ts12
            .as_ref()
            .map_err(|fault| Incompatibility::TypeMetadata(fault.clone()))?;
        if let Some(found) = ts12
            .as_ref()
            .and_then(|metadata| metadata.definition(type_id, self.credential, self.verifier.held))
        {
            let (definition, schema) = found.map_err(Incompatibility::TypeMetadata)?;
            return self.project(
                Ok(definition),
                SourceKind::TypeMetadata,
                Rulebook::Ts12(schema),
            );
        }
        if self.paso.is_some() || ts12.is_some() {
            return Err(Incompatibility::TypeUndeclared);
        }
        match self.configuration.definition(type_id, self.credential) {
            Some(definition) => {
                self.project(Ok(definition.clone()), SourceKind::Configuration, rulebook)
            }
            None => Err(Incompatibility::TypeUnsupported),
        }
    }

    /// `definition`, of `source`, projected to the wallet's language.
    fn project(
        &self,
        definition: Result<Definition, DefinitionError>,
        source: SourceKind,
        rulebook: Rulebook,
    ) -> Result<Projected, Incompatibility> {
        definition
            .map_err(|error| Incompatibility::Definition(source, error))?
            .project(self.language, source, rulebook)
            .map_err(Incompatibility::Language)
    }
}

impl Definitions for CredentialSources<'_> {
    /// The entry's ad-hoc metadata when it has one, with no other source after a failed one
    /// (PaSO Proof Metadata, Section 5.3); else [`CredentialSources::served`].
    fn serve(&self, entry: &Entry) -> Result<Projected, Incompatibility> {
        let type_id = entry.type_id();
        match entry.metadata() {
            Some(metadata) => {
                let definition = metadata
                    .verify(type_id, self.credential, self.verifier)
                    .map_err(Incompatibility::AdHoc)?;
                self.project(definition, SourceKind::AdHoc, Rulebook::of_type(type_id))
            }
            None => self.served(type_id),
        }
    }
}
