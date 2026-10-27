//! Discovery and validation (PaSO Core, Section 7.4.2): each candidate credential takes the
//! first entry, in array order, that targets it, whose type it supports in the wallet's
//! language, whose payload conforms, whose resources verify, and that renders in full. A
//! credential with none is excluded.

use siros_codec::date::DateTime;
use siros_credential::{Credential, EntryRef, Format};
use siros_display::{DisplayCache, Locale};
use siros_oid4vp::RequestSignature;
use siros_trust::TrustStore;

use crate::definition::DefinitionError;
use crate::entry::Entry;
use crate::error::{EntryPosition, TransactionDataError};
use crate::fetched::{Fetched, Step};
use crate::image::ImageFault;
use crate::payload::{conform, Location, PayloadFault, ValueFault, Values};
use crate::projection::Unmatched;
use crate::render::{layout, RenderFault, Rendering};
use crate::sources::{
    Configuration, CredentialMetadataFault, Rulebook, Served, SignedFault, SourceKind, Sources,
    Ts12Fault, Verifier,
};
use crate::ts12::read::Ts12PayloadFault;
use crate::ts12::Ts12Payload;
use crate::view::TransactionView;

/// Why an entry is not compatible with a credential (PaSO Core, Section 7.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Incompatibility {
    /// The credential is no SD-JWT VC: transaction data binds into an SD-JWT VC's KB-JWT only
    /// (EC TS12 v1.0.1, Section 1.2; OpenID4VP 1.0, B.3.3).
    Format,
    /// No source defines the entry's type for the credential.
    TypeUnsupported,
    /// The entry's ad-hoc metadata JWT is invalid; no other source serves the entry (PaSO Proof
    /// Metadata, Section 5.3).
    AdHoc(SignedFault),
    /// The credential's signed credential metadata is invalid, which excludes the credential
    /// (PaSO Proof Metadata, Section 7).
    CredentialMetadata(CredentialMetadataFault),
    /// The credential's TS12 type metadata gives no definition of the type.
    TypeMetadata(Ts12Fault),
    /// The definition of this source breaks PaSO Proof Metadata, Section 3, which makes the
    /// type unsupported by the credential (Section 3.3).
    Definition(SourceKind, DefinitionError),
    /// A localised array has no entry for the wallet's language (PaSO View, Section 4).
    Language(Unmatched),
    /// The payload does not conform to the definition.
    Payload(PayloadFault),
    /// The payload breaks the schema of its TS12 type.
    Ts12Payload(Ts12PayloadFault),
    /// A TS12 payload value at this location is no value of its type.
    Ts12Value(Location, ValueFault),
    /// The image at this location is refused.
    Image(Location, ImageFault),
    /// The entry does not render in full (PaSO View, Section 2).
    Render(RenderFault),
}

impl Incompatibility {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Format => "transaction_data_format_unsupported",
            Self::TypeUnsupported => "transaction_data_type_unsupported",
            Self::AdHoc(fault) => fault.code(),
            Self::CredentialMetadata(fault) => fault.code(),
            Self::TypeMetadata(fault) => fault.code(),
            Self::Definition(_, error) => error.code(),
            Self::Language(unmatched) => unmatched.code(),
            Self::Payload(fault) => fault.code(),
            Self::Ts12Payload(fault) => fault.code(),
            Self::Ts12Value(_, fault) => fault.code(),
            Self::Image(_, fault) => fault.code(),
            Self::Render(fault) => fault.code(),
        }
    }
}

siros_codec::display_code!(Incompatibility);

impl std::error::Error for Incompatibility {}

/// What the evaluation of an entry for a credential reads.
#[derive(Clone, Copy)]
pub struct Context<'c> {
    /// The trust store (H4), against which `x5c` chains are validated.
    pub trust: &'c TrustStore,
    /// The host's responses to the fetches transaction data asked for.
    pub fetched: &'c Fetched,
    /// The display metadata the host holds, which locates signed credential metadata.
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

/// Why an image is not ready: its fetch, or its fault.
enum Unready {
    Fetch(siros_oid4vp::Fetch),
    Fault(ImageFault),
}

/// An entry a credential takes, with its view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken {
    entry: EntryPosition,
    view: TransactionView,
}

/// What a candidate credential takes: an entry, or nothing, with why each entry that targets it
/// is not compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// The first compatible entry.
    Takes(Taken),
    /// No entry is compatible, each for its reason: the credential is excluded.
    Excluded(Vec<(EntryPosition, Incompatibility)>),
}

/// A credential the first match excluded, and why each entry that targets it is not compatible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    /// The credential, by `credentialId` and instance.
    pub credential: EntryRef,
    /// Each entry that targets it, with why it is not compatible.
    pub causes: Vec<(EntryPosition, Incompatibility)>,
}

impl Taken {
    /// The entry's position in the request's `transaction_data`.
    #[must_use]
    pub fn entry(&self) -> EntryPosition {
        self.entry
    }

    /// The view of the entry for the credential.
    #[must_use]
    pub fn view(&self) -> &TransactionView {
        &self.view
    }
}

impl Context<'_> {
    fn sources(&self) -> Sources<'_> {
        Sources {
            verifier: Verifier {
                trust: self.trust,
                fetched: self.fetched,
                now: self.now,
            },
            display: self.display,
            configuration: self.configuration,
            language: self.language,
        }
    }

    /// What `credential` takes of `entries`, those that target it in array order (Section 7.4.2,
    /// steps 2 and 3). The step is a fetch while the host has not given a document.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::Unsigned`] when the request arrived unsigned and a PaSO source
    /// serves an entry the credential would take (PaSO Core, Section 3).
    pub fn first_match(
        &self,
        entries: &[&Entry],
        credential: &Credential,
    ) -> Result<Step<Selection>, TransactionDataError> {
        let mut causes = Vec::new();
        for entry in entries {
            match self.evaluate(entry, credential)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(Ok(view)) => {
                    return Ok(Step::Done(Selection::Takes(Taken {
                        entry: entry.position(),
                        view,
                    })))
                }
                Step::Done(Err(cause)) => causes.push((entry.position(), cause)),
            }
        }
        Ok(Step::Done(Selection::Excluded(causes)))
    }

    /// Whether some source defines `entry`'s type for `credential` (OpenID4VP 1.0, Section
    /// 5.1). The step is a fetch while the host has not given a document.
    pub fn knows(&self, entry: &Entry, credential: &Credential) -> Step<bool> {
        if credential.format() != Format::SdJwtVc {
            return Step::Done(false);
        }
        match self.sources().serve(entry, credential) {
            Ok(Step::Fetch(fetch)) => Step::Fetch(fetch),
            Ok(Step::Done(_)) => Step::Done(true),
            Err(_) => Step::Done(false),
        }
    }

    /// The view of `entry` for `credential`, or why the entry is not compatible.
    fn evaluate(
        &self,
        entry: &Entry,
        credential: &Credential,
    ) -> Result<Step<Result<TransactionView, Incompatibility>>, TransactionDataError> {
        if credential.format() != Format::SdJwtVc {
            return Ok(Step::Done(Err(Incompatibility::Format)));
        }
        let served = match self.sources().serve(entry, credential) {
            Ok(Step::Fetch(fetch)) => return Ok(Step::Fetch(fetch)),
            Ok(Step::Done(served)) => served,
            Err(cause) => return Ok(Step::Done(Err(cause))),
        };
        if self.signature == RequestSignature::Unsigned && served.source.is_paso() {
            return Err(TransactionDataError::Unsigned(entry.position()));
        }
        Ok(self.view(entry, &served))
    }

    /// The view of `entry` under `served`.
    fn view(
        &self,
        entry: &Entry,
        served: &Served,
    ) -> Step<Result<TransactionView, Incompatibility>> {
        let projected = match served.definition.project(self.language) {
            Ok(projected) => projected,
            Err(unmatched) => return Step::Done(Err(Incompatibility::Language(unmatched))),
        };
        let payload = entry.payload();
        let (values, floors) = match self.values(entry, served) {
            Ok(typed) => typed,
            Err(cause) => return Step::Done(Err(cause)),
        };
        let mut ready = Vec::new();
        for placed in layout(&projected, payload, &values) {
            let location = placed.location().clone();
            let verified = placed.ready(|image| match image.verify(self.fetched) {
                Ok(Step::Done(image)) => Ok(image),
                Ok(Step::Fetch(fetch)) => Err(Unready::Fetch(fetch)),
                Err(fault) => Err(Unready::Fault(fault)),
            });
            match verified {
                Ok(placed) => ready.push(placed),
                Err(Unready::Fetch(fetch)) => return Step::Fetch(fetch),
                Err(Unready::Fault(fault)) => {
                    return Step::Done(Err(Incompatibility::Image(location, fault)))
                }
            }
        }
        let rendering = Rendering {
            type_id: entry.type_id(),
            source: served.source,
            rulebook: served.rulebook,
            projected: &projected,
            payload,
            values: &values,
            floors: &floors,
            signature: self.signature,
        };
        Step::Done(rendering.render(ready).map_err(Incompatibility::Render))
    }

    /// The typed values of `entry`'s payload under the rulebook of `served`, and the floors of
    /// a TS12 payload's leaves.
    fn values(
        &self,
        entry: &Entry,
        served: &Served,
    ) -> Result<(Values, Vec<(Location, crate::definition::Prominence)>), Incompatibility> {
        match served.rulebook {
            Rulebook::Generic => conform(entry.payload(), &served.definition)
                .map(|values| (values, Vec::new()))
                .map_err(Incompatibility::Payload),
            Rulebook::Ts12(rulebook) => {
                let payload = Ts12Payload::parse(rulebook, entry.payload(), self.now)
                    .map_err(Incompatibility::Ts12Payload)?;
                let typed = payload
                    .leaves()
                    .typed(entry.payload())
                    .map_err(|(location, fault)| Incompatibility::Ts12Value(location, fault))?;
                Ok((typed.values, typed.floors))
            }
        }
    }
}
