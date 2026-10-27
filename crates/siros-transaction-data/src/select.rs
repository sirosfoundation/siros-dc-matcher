//! Discovery and validation (PaSO Core, Section 7.4.2): each candidate credential takes the
//! first entry, in array order, that targets it, whose type it supports in the wallet's
//! language, whose payload conforms, that renders within the cap, whose resources verify, and
//! that renders in full. A credential with none is excluded.

use siros_codec::date::DateTime;
use siros_credential::EntryRef;
use siros_oid4vp::RequestSignature;

use crate::definition::{DefinitionError, Prominence};
use crate::entry::Entry;
use crate::error::{EntryPosition, TransactionDataError};
use crate::fetched;
use crate::fetched::{Fetched, Step};
use crate::hash::AlgClaim;
use crate::image::ImageFault;
use crate::payload::{conform, Location, PayloadFault, Typed, ValueFault, Values};
use crate::projection::{Projected, Unmatched};
use crate::render::{layout, Ready, RenderFault, Rendering, MAX_ITEMS};
#[cfg(feature = "wallet")]
use crate::sources::{CredentialMetadataFault, SignedFault, Ts12Fault};
use crate::sources::{Rulebook, SourceKind};
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
    /// The credential's own metadata declares every type it supports, and not this one; the
    /// configuration serves only credentials without metadata of their own (EC TS12 v1.0.1,
    /// Section 3.2, step 2; PaSO Proof Metadata, Section 3).
    TypeUndeclared,
    /// The entry's ad-hoc metadata JWT is invalid; no other source serves the entry (PaSO Proof
    /// Metadata, Section 5.3).
    #[cfg(feature = "wallet")]
    AdHoc(SignedFault),
    /// The host holds no issuer metadata of the credential's configuration, which tells whether
    /// it is a PaSO Credential: the credential is excluded.
    IssuerMetadataNotHeld,
    /// The credential's signed credential metadata is not held or invalid, which excludes the
    /// credential (PaSO Proof Metadata, Sections 3 and 7).
    #[cfg(feature = "wallet")]
    CredentialMetadata(CredentialMetadataFault),
    /// The credential's TS12 type metadata gives no definition of the type.
    #[cfg(feature = "wallet")]
    TypeMetadata(Ts12Fault),
    /// The definition of this source breaks PaSO Proof Metadata, Section 3, which makes the
    /// type unsupported by the credential (Section 3.3).
    Definition(SourceKind, DefinitionError),
    /// A localised array has no entry for the wallet's language (PaSO View, Section 4).
    Language(Unmatched),
    /// The entry has no `transaction_data_hashes_alg`, which a TS12 rulebook requires (EC TS12
    /// v1.0.1, Section 4.2).
    HashesAlgAbsent,
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
            Self::TypeUndeclared => "transaction_data_type_undeclared",
            Self::IssuerMetadataNotHeld => "transaction_data_issuer_metadata_not_held",
            #[cfg(feature = "wallet")]
            Self::AdHoc(fault) => fault.code(),
            #[cfg(feature = "wallet")]
            Self::CredentialMetadata(fault) => fault.code(),
            #[cfg(feature = "wallet")]
            Self::TypeMetadata(fault) => fault.code(),
            Self::Definition(_, error) => error.code(),
            Self::Language(unmatched) => unmatched.code(),
            Self::HashesAlgAbsent => "transaction_data_hashes_alg_absent",
            Self::Payload(fault) => fault.code(),
            Self::Ts12Payload(fault) => fault.code(),
            Self::Ts12Value(_, fault) => fault.code(),
            Self::Image(_, fault) => fault.code(),
            Self::Render(fault) => fault.code(),
        }
    }

    /// Whether a source defines the entry's type for the credential, though the entry is not
    /// compatible: every cause but a format without transaction data and a type no source
    /// declares (OpenID4VP 1.0, Section 5.1).
    #[must_use]
    pub fn type_defined(&self) -> bool {
        match self {
            Self::Format | Self::TypeUnsupported | Self::TypeUndeclared => false,
            #[cfg(feature = "wallet")]
            Self::AdHoc(_) | Self::CredentialMetadata(_) | Self::TypeMetadata(_) => true,
            Self::IssuerMetadataNotHeld
            | Self::Definition(..)
            | Self::Language(_)
            | Self::HashesAlgAbsent
            | Self::Payload(_)
            | Self::Ts12Payload(_)
            | Self::Ts12Value(..)
            | Self::Image(..)
            | Self::Render(_) => true,
        }
    }
}

siros_codec::display_code!(Incompatibility);

impl std::error::Error for Incompatibility {}

/// What serves a credential's definitions: the wallet's sources, or the projections a credential
/// was registered with.
pub trait Definitions {
    /// The definition of `entry`'s type for the credential, projected to the wallet's language.
    ///
    /// # Errors
    ///
    /// [`Incompatibility`]: why no definition serves the entry.
    fn serve(&self, entry: &Entry) -> Result<Projected, Incompatibility>;
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

/// What the first match reads beside a credential's definitions: the host's answers to the
/// image fetches, whether the request arrived signed, and the time.
#[derive(Debug, Clone, Copy)]
pub struct Selector<'s> {
    /// The host's responses to the image fetches transaction data asked for.
    pub fetched: &'s Fetched,
    /// Whether the request arrived signed.
    pub signature: RequestSignature,
    /// The time, against which a TS12 payload's dates are read.
    pub now: DateTime,
}

impl Selector<'_> {
    /// What a credential whose definitions `definitions` serves takes of `entries`, those that
    /// target it in array order (Section 7.4.2, steps 2 and 3). The step is a fetch while the
    /// host has not given an image.
    ///
    /// # Errors
    ///
    /// [`TransactionDataError::Unsigned`] when the request arrived unsigned and PaSO metadata
    /// serves an entry (PaSO Core, Section 3).
    pub fn first_match(
        &self,
        entries: &[&Entry],
        definitions: &impl Definitions,
    ) -> Result<Step<Selection>, TransactionDataError> {
        let mut causes = Vec::new();
        for entry in entries {
            let projected = match definitions.serve(entry) {
                Ok(projected) => projected,
                Err(cause) => {
                    causes.push((entry.position(), cause));
                    continue;
                }
            };
            if self.signature == RequestSignature::Unsigned && projected.source().is_paso() {
                return Err(TransactionDataError::Unsigned(entry.position()));
            }
            match self.view(entry, &projected) {
                Ok(step) => {
                    return Ok(step.map(|view| {
                        Selection::Takes(Taken {
                            entry: entry.position(),
                            view,
                        })
                    }))
                }
                Err(cause) => causes.push((entry.position(), cause)),
            }
        }
        Ok(Step::Done(Selection::Excluded(causes)))
    }

    /// The view of `entry` under `projected`: its typed values, then the cap on the items it
    /// would show, then its images verified, then the rendering. Under a TS12 rulebook an image
    /// that does not verify is left out (PaSO Proof SD-JWT-VC and SVG, Section 2).
    fn view(
        &self,
        entry: &Entry,
        projected: &Projected,
    ) -> Result<Step<TransactionView>, Incompatibility> {
        let payload = entry.payload();
        let (values, floors) = self.values(entry, projected)?;
        let placed = layout(projected, payload, &values);
        let items = placed.len() + projected.ui_elements();
        if items > MAX_ITEMS {
            return Err(Incompatibility::Render(RenderFault::TooManyItems(items)));
        }
        let mut ready = Vec::with_capacity(placed.len());
        let mut absent = Vec::new();
        for place in placed {
            let value = match place.value() {
                Typed::Image(image) => match image.verify(self.fetched) {
                    Ok(step) => Ready::Image(fetched!(step)),
                    Err(fault) => match projected.rulebook() {
                        Rulebook::Ts12(_) => {
                            absent.push((place.location().clone(), fault));
                            continue;
                        }
                        Rulebook::Generic => {
                            return Err(Incompatibility::Image(place.location().clone(), fault))
                        }
                    },
                },
                Typed::Scalar(scalar) => Ready::Scalar(scalar.clone()),
                Typed::LabelOnly => Ready::LabelOnly,
                Typed::Template(text, inner) => Ready::Template(text.clone(), *inner),
            };
            ready.push(place.with(value));
        }
        let rendering = Rendering {
            type_id: entry.type_id(),
            projected,
            payload,
            values: &values,
            floors: &floors,
            signature: self.signature,
        };
        rendering
            .render(ready, absent)
            .map(Step::Done)
            .map_err(Incompatibility::Render)
    }

    /// The typed values of `entry`'s payload under the rulebook of `projected`, and the floors
    /// of a TS12 payload's leaves.
    fn values(
        &self,
        entry: &Entry,
        projected: &Projected,
    ) -> Result<(Values, Vec<(Location, Prominence)>), Incompatibility> {
        match projected.rulebook() {
            Rulebook::Generic => conform(
                entry.payload(),
                projected.claims().iter().map(|claim| claim.definition()),
            )
            .map(|values| (values, Vec::new()))
            .map_err(Incompatibility::Payload),
            Rulebook::Ts12(rulebook) => {
                if entry.hashes().claim() == AlgClaim::Omitted {
                    return Err(Incompatibility::HashesAlgAbsent);
                }
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
