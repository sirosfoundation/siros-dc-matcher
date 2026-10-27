//! OpenID4VP 1.0 transaction data for the SIROS wallet core, on the PaSO model (PaSO Core, View
//! and Proof Metadata, draft 2), with the four types of EC TS12 v1.0.1 as built-in rulebooks.
//!
//! | Requirement | API |
//! | --- | --- |
//! | One definition form: a `transaction_data_types` entry (Proof Metadata, Section 3), its labels typed by role, their limits and character rules set by the source ([`LabelRules`]: PaSO's Section 3.3, or TS12's Section 3.3.3), its structural rules (Section 3.3) | [`Definition`], [`ClaimDefinition`], [`UiLabels`], [`LabelText`], [`ValueType`] |
//! | Sources, each a parser into it: the signed credential metadata JWT (Sections 4 and 7), TS12 v1.0.1 type metadata (`lang` → `locale`, `label` → `name`, `visualisation` as [`Prominence`]), the host's [`Configuration`], and the entry's ad-hoc metadata JWT (Section 5). Ad-hoc first; then the credential's own metadata, which declares every type it supports and fails closed; else, for a credential known to have no metadata of its own, the configuration | [`SourceKind`], [`Configuration::parse`] |
//! | Metadata is input: the host holds signed credential metadata, Type Metadata and key sets, fetched and renewed outside presentations, and records what is absent (Proof Metadata, Sections 6 and 8); the wallet verifies each every time it loads it | [`HeldMetadata`], [`HeldDocument::absent`], [`HeldJwt::verify_fetched`], [`HeldMetadata::wanted`] |
//! | The projection to the wallet's language: one entry per array, made only by the locale function (View, Section 4), with its source and rulebook, written deterministically and read back | [`Definition::project`], [`Projected::to_json`], [`Projected::parse`], [`Context::served`] |
//! | T1: entries: base64url JSON without repeated names, `type`, `credential_ids` of DCQL query ids, `payload`, ad-hoc `metadata`, `transaction_data_hashes_alg` as an array or CS-12's string | [`Entry::parse`] |
//! | The request's rules: PaSO-targeted entries only in a signed request (Core, Section 3); the targeted queries in one credential set, its alternatives transposable (Core, Section 7.4.1) | [`check_request`] |
//! | Payload conformance: coverage, `#integrity` companions of images, mandatory claims, value types (Core, Section 7.4.2; View, Section 3) | [`PayloadFault`], [`Scalar`] |
//! | Images: Data URLs of PNG, JPEG and SVG, `https` URLs with `#integrity` fetched with at most 3 redirects, 512 KiB and 2048 px (View, Section 3); SVG within a static subset, its CSS read by a CSS Syntax 3 tokenizer, every URL a fragment, a PNG or JPEG Data URL or a pinned `https` URL, at most [`MAX_RESOURCES`] resources, each an image or a font (SVG module, Section 3); a TS12 logo that does not verify is left out | [`VerifiedImage`], [`ImageFault`], [`SvgFault`], [`CssFault`], [`TransactionView::absent_images`] |
//! | Generic rendering: rows in claims order, `null` paths, `template:` as segments of text and typed values, label limits after interpolation, at most 200 items counted before any image is verified, `security_hint` as given (View, Section 2) | [`TransactionView`], [`Segment`], [`RenderFault`] |
//! | Selection: each candidate credential takes its first compatible entry (Core, Section 7.4.2) | [`Selector::first_match`] over [`Definitions`], [`Context::first_match`], [`Selection`] |
//! | T3, T6: the B.3.3.1 hash over the entry as received, one algorithm per credential, `transaction_data_hashes_alg` repeated when the request carried it; `jti`, `response_mode` and `amr` under a TS12 rulebook; SD-JWT VC only | [`Binding::kb_jwt_claims`], [`Amr`] |
//!
//! Every refusal of a request is a [`TransactionDataError`]; every reason an entry does not
//! serve a credential is an [`Incompatibility`].
//!
//! Without the default feature `wallet` the crate holds what the credential picker runs over a
//! registration (K2): definitions, the projection reader, payload conformance, selection over
//! [`Definitions`], and rendering. It links no X.509, ECDSA or trust code. The picker cannot
//! verify two things the wallet verifies at consent: an image at a remote URL, which needs a
//! fetch, and an entry's ad-hoc metadata JWT, which needs the trust store.

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(unused_results)]
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::let_underscore_must_use, clippy::let_underscore_untyped)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod amr;
#[cfg(feature = "wallet")]
mod context;
mod currency;
mod definition;
mod entry;
mod error;
mod fetched;
mod hash;
mod image;
mod integrity;
mod json;
mod output;
mod payload;
mod projection;
mod render;
mod select;
mod sets;
mod sources;
mod ts12;
mod type_id;
mod view;

pub use amr::{Amr, AmrCategories, Factor, Inherence, Knowledge, Possession};
#[cfg(feature = "wallet")]
pub use context::Context;
pub use currency::CurrencyCode;
pub use definition::{
    ActionLabel, BaseType, ClaimDefinition, ClaimDisplay, ClaimFault, ClaimIndex, ClaimName,
    Definition, DefinitionError, DefinitionMember, Description, EntryFault, HintEntry, LabelFormat,
    LabelLength, LabelRole, LabelRules, LabelText, LabelsFault, Limit, Localizations, Mandatory,
    OtherUiElement, PayloadPath, Prominence, SecurityHint, TextFault, TransactionTitle,
    UiElementKey, UiLabel, UiLabels, ValueType, MAX_CLAIMS,
};
pub use entry::Entry;
pub use error::{EntryMember, EntryPosition, EntryRefusal, TransactionDataError};
pub use fetched::{FetchFault, Fetched, Step};
pub use hash::{AlgClaim, HashAlg, HashesAlgFault};
pub use image::{
    CssFault, Dimensions, ImageFault, ImageFormat, ImageRef, RasterFault, Resource, SvgFault,
    VerifiedImage, MAX_DEPTH, MAX_IMAGE_BYTES, MAX_IMAGE_PIXELS, MAX_RESOURCES,
};
pub use integrity::{Integrity, IntegrityFault};
pub use output::{Binding, Jti, KbJwtInputs};
pub use payload::{
    CurrencyAmount, Frequency, IsoDateTime, IsoTime, Location, NumberText, PayloadFault,
    PayloadText, Scalar, Step as LocationStep, Typed, ValueFault,
};
pub use projection::{Projected, ProjectedClaim, ProjectionError, ProjectionMember, Unmatched};
pub use render::{RenderFault, TemplateFault, MAX_ITEMS};
pub use select::{Definitions, Exclusion, Incompatibility, Selection, Selector, Taken};
pub use sets::{SetPosition, SetsFault};
pub use sources::{
    AdHocMetadata, Configuration, ConfigurationError, ConfigurationMember, Configured,
    ConfiguredFault, ConfiguredType, Rulebook, SourceKind,
};
#[cfg(feature = "wallet")]
pub use sources::{
    CredentialMetadataFault, HeldDocument, HeldError, HeldJwt, HeldMetadata, JwkFault, JwsFault,
    KeySetFault, MetadataClaim, Renewal, SignedFault, Ts12Fault, Ts12Member, Wanted, WantedFault,
};
pub use ts12::read::{MemberPath, Ts12PayloadFault};
pub use type_id::{EmptyTypeId, Ts12Type, TypeFamily, TypeId};
pub use view::{
    Interpolated, Row, RowValue, Segment, ShownLabel, TransactionView, UnsignedWarning,
};

/// Checks the request's rules on its `entries` as a whole: an unsigned request carries no
/// PaSO-targeted entry (PaSO Core, Section 3), and the credential sets of `query` hold the
/// queries the entries target as Section 7.4.1 says.
///
/// # Errors
///
/// [`TransactionDataError::Unsigned`] and [`TransactionDataError::CredentialSets`].
pub fn check_request(
    entries: &[Entry],
    query: &siros_dcql::DcqlQuery,
    signature: siros_oid4vp::RequestSignature,
) -> Result<(), TransactionDataError> {
    if signature == siros_oid4vp::RequestSignature::Unsigned {
        if let Some(entry) = entries
            .iter()
            .find(|e| e.type_id().family() == TypeFamily::Paso)
        {
            return Err(TransactionDataError::Unsigned(entry.position()));
        }
    }
    sets::check(entries, query).map_err(TransactionDataError::CredentialSets)
}
