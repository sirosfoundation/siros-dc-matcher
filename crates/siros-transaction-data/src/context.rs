//! The wallet's selection: a credential's definitions served by its sources, verified against
//! the trust store and the metadata the host holds, then the first match of [`Selector`].

use siros_codec::date::DateTime;
use siros_credential::Credential;
use siros_display::{DisplayCache, Locale};
use siros_oid4vp::RequestSignature;
use siros_trust::TrustStore;

use crate::entry::Entry;
use crate::error::TransactionDataError;
use crate::fetched::{Fetched, Step};
use crate::projection::Projected;
use crate::select::{Incompatibility, Selection, Selector};
use crate::sources::{Configuration, CredentialSources, HeldMetadata, Verifier};
use crate::type_id::TypeId;

/// What the evaluation of an entry for a credential reads.
#[derive(Clone, Copy)]
pub struct Context<'c> {
    /// The trust store (H4), against which `x5c` chains are validated.
    pub trust: &'c TrustStore,
    /// The metadata the host holds: signed credential metadata, type metadata, key sets.
    pub held: &'c HeldMetadata,
    /// The host's responses to the image fetches transaction data asked for.
    pub fetched: &'c Fetched,
    /// The display metadata the host holds, which names the PaSO Credentials.
    pub display: &'c DisplayCache,
    /// The host's configured definitions.
    pub configuration: &'c Configuration,
    /// The wallet's language.
    pub language: &'c Locale,
    /// Whether the request arrived signed.
    pub signature: RequestSignature,
    /// The time.
    pub now: DateTime,
}

impl<'c> Context<'c> {
    /// The sources of `credential`, its own metadata loaded.
    fn sources(
        &self,
        credential: &'c Credential,
    ) -> Result<CredentialSources<'c>, Incompatibility> {
        let verifier = Verifier {
            trust: self.trust,
            held: self.held,
            now: self.now,
        };
        CredentialSources::load(
            credential,
            verifier,
            self.display,
            self.configuration,
            self.language,
        )
    }

    /// What `credential` takes of `entries`, those that target it in array order (PaSO Core,
    /// Section 7.4.2, steps 2 and 3). A credential whose own metadata is not valid takes none,
    /// each entry with that cause. The step is a fetch while the host has not given an image.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::Unsigned`] when the request arrived unsigned and PaSO metadata
    /// serves an entry the credential would take (PaSO Core, Section 3).
    pub fn first_match(
        &self,
        entries: &[&Entry],
        credential: &'c Credential,
    ) -> Result<Step<Selection>, TransactionDataError> {
        let selector = Selector {
            fetched: self.fetched,
            signature: self.signature,
            now: self.now,
        };
        match self.sources(credential) {
            Ok(sources) => selector.first_match(entries, &sources),
            Err(cause) => Ok(Step::Done(Selection::Excluded(
                entries
                    .iter()
                    .map(|entry| (entry.position(), cause.clone()))
                    .collect(),
            ))),
        }
    }

    /// Whether a source defines `entry`'s type for `credential` (OpenID4VP 1.0, Section 5.1),
    /// though the entry may not be compatible.
    pub fn knows(&self, entry: &Entry, credential: &'c Credential) -> bool {
        let served = self
            .sources(credential)
            .and_then(|sources| crate::select::Definitions::serve(&sources, entry).map(drop));
        served
            .as_ref()
            .err()
            .is_none_or(Incompatibility::type_defined)
    }

    /// The definition of `type_id` that `credential`'s own metadata or the configuration
    /// gives, in the wallet's language: what a registration projects (K2).
    ///
    /// # Errors
    ///
    /// [`Incompatibility`]: why no source serves the type for the credential.
    pub fn served(
        &self,
        type_id: &TypeId,
        credential: &'c Credential,
    ) -> Result<Projected, Incompatibility> {
        self.sources(credential)?.served(type_id)
    }
}
