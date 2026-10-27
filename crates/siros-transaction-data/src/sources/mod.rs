//! The sources of a transaction data type's definition, each a parser into the one form
//! ([`Definition`]), and their precedence for one entry and one credential: the entry's ad-hoc
//! metadata, then the credential's own metadata, then the host's configuration.

mod adhoc;
mod config;
mod issuer_keys;
mod jws;
mod paso;
mod signed;
mod ts12;
mod ts12_map;

use siros_credential::Credential;
use siros_display::DisplayCache;

use crate::definition::{Definition, DefinitionError};
use crate::entry::Entry;
use crate::fetched::Step;
use crate::select::Incompatibility;
use crate::type_id::Ts12Type;

pub use adhoc::AdHocMetadata;
pub use config::{
    Configuration, ConfigurationError, ConfigurationMember, Configured, ConfiguredFault,
    ConfiguredType,
};
pub use issuer_keys::KeySetFault;
pub use jws::{JwkFault, JwsFault};
pub use paso::CredentialMetadataFault;
pub use signed::{MetadataClaim, SignedFault};
pub use ts12::{Ts12Fault, Ts12Member};

pub(crate) use signed::Verifier;

use paso::CredentialMetadata;
use ts12::TypeMetadata;

/// Where a definition comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// The entry's ad-hoc metadata JWT (PaSO Proof Metadata, Section 5).
    AdHoc,
    /// The credential's signed credential metadata JWT (PaSO Proof Metadata, Section 4).
    CredentialMetadata,
    /// The credential's SD-JWT VC Type Metadata (EC TS12 v1.0.1, Section 4.1).
    TypeMetadata,
    /// The host's configuration.
    Configuration,
}

impl SourceKind {
    /// Whether the source is PaSO's signed metadata, which a signed request must accompany
    /// (PaSO Core, Section 3).
    #[must_use]
    pub fn is_paso(self) -> bool {
        matches!(self, Self::AdHoc | Self::CredentialMetadata)
    }
}

/// The rulebook of an entry's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rulebook {
    /// A type of EC TS12 v1.0.1: its typed payload, and `jti`, `response_mode` and `amr` in
    /// the KB-JWT.
    Ts12(Ts12Type),
    /// The definition alone: PaSO payload conformance (PaSO Core, Section 7.4.2).
    Generic,
}

/// The definition that serves an entry for a credential, where it comes from, and the
/// rulebook of the payload.
pub(crate) struct Served {
    pub(crate) definition: Definition,
    pub(crate) source: SourceKind,
    pub(crate) rulebook: Rulebook,
}

/// What the sources read: the verification inputs, the host's display metadata and its
/// configuration.
#[derive(Clone, Copy)]
pub(crate) struct Sources<'s> {
    pub(crate) verifier: Verifier<'s>,
    pub(crate) display: &'s DisplayCache,
    pub(crate) configuration: &'s Configuration,
}

impl Sources<'_> {
    /// The definition of `entry`'s type for `credential`: the entry's ad-hoc metadata when it
    /// has one, with no other source after a failed one (Section 5.3); else the credential's
    /// signed credential metadata, an invalid one excluding the credential (Section 7); else its
    /// TS12 type metadata; else the host's configuration. The step is a fetch while the host
    /// has not given a document.
    ///
    /// # Errors
    ///
    /// [`Incompatibility`]: why no source serves the type.
    pub(crate) fn serve(
        &self,
        entry: &Entry,
        credential: &Credential,
    ) -> Result<Step<Served>, Incompatibility> {
        let type_id = entry.type_id();
        let builtin = type_id.rulebook();
        let rulebook = builtin.map_or(Rulebook::Generic, Rulebook::Ts12);
        if let Some(metadata) = entry.metadata() {
            let definition = match metadata
                .verify(type_id, credential, self.verifier)
                .map_err(Incompatibility::AdHoc)?
            {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(definition) => definition,
            };
            return served(definition, SourceKind::AdHoc, rulebook);
        }
        if let Some(uri) = self.display.credential_metadata_uri(credential) {
            let metadata = match CredentialMetadata::load(uri, credential, self.verifier)
                .map_err(Incompatibility::CredentialMetadata)?
            {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(metadata) => metadata,
            };
            if let Some(definition) = metadata.definition(type_id) {
                return served(definition.clone(), SourceKind::CredentialMetadata, rulebook);
            }
        }
        let fetched = self.verifier.fetched;
        let metadata =
            match TypeMetadata::load(credential, fetched).map_err(Incompatibility::TypeMetadata)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(metadata) => metadata,
            };
        if let Some(found) = metadata.and_then(|m| m.definition(type_id, credential, fetched)) {
            return match found.map_err(Incompatibility::TypeMetadata)? {
                Step::Fetch(fetch) => Ok(Step::Fetch(fetch)),
                Step::Done((definition, schema)) => Ok(Step::Done(Served {
                    definition,
                    source: SourceKind::TypeMetadata,
                    rulebook: Rulebook::Ts12(schema),
                })),
            };
        }
        match self.configuration.definition(type_id, credential) {
            Some(definition) => served(Ok(definition.clone()), SourceKind::Configuration, rulebook),
            None => Err(Incompatibility::TypeUnsupported),
        }
    }
}

/// The definition `definition` of `source`, or why it breaks Section 3.
fn served(
    definition: Result<Definition, DefinitionError>,
    source: SourceKind,
    rulebook: Rulebook,
) -> Result<Step<Served>, Incompatibility> {
    let definition = definition.map_err(|error| Incompatibility::Definition(source, error))?;
    Ok(Step::Done(Served {
        definition,
        source,
        rulebook,
    }))
}
