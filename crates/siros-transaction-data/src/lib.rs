//! OpenID4VP 1.0 transaction data for the SIROS wallet core, on the PaSO model (PaSO Core, View
//! and Proof Metadata, draft 2), with the four types of EC TS12 v1.0.1 as built-in rulebooks.
//!
//! | Requirement | API |
//! | --- | --- |
//! | One definition form: a `transaction_data_types` entry (Proof Metadata, Section 3), its labels typed by role with their limits and character rules, its structural rules (Section 3.3) | [`Definition`], [`ClaimDefinition`], [`UiLabels`], [`LabelText`], [`ValueType`] |
//! | Sources, each a parser into it: the signed credential metadata JWT (Sections 4 and 7), TS12 v1.0.1 type metadata (`lang` → `locale`, `label` → `name`, `visualisation` as [`Prominence`]), the host's [`Configuration`], and the entry's ad-hoc metadata JWT (Section 5); ad-hoc first, then the credential's own metadata, then the configuration | [`SourceKind`], [`Configuration::parse`] |
//! | The projection to the wallet's language: one entry per array, made only by the locale function (View, Section 4), serialised deterministically | [`Definition::project`], [`Projected::to_json`] |
//! | T1: entries: base64url JSON without repeated names, `type`, `credential_ids` of DCQL query ids, `payload`, ad-hoc `metadata`, `transaction_data_hashes_alg` as an array or CS-12's string | [`Entry::parse`] |
//! | The request's rules: PaSO-targeted entries only in a signed request (Core, Section 3); the targeted queries in one credential set, its alternatives transposable (Core, Section 7.4.1) | [`check_request`] |
//! | Payload conformance: coverage, mandatory claims, value types (Core, Section 7.4.2; View, Section 3) | [`PayloadFault`], [`Scalar`] |
//! | Images: Data URLs of PNG, JPEG and SVG, `https` URLs with `#integrity`, 512 KiB and 2048 px, SVG references pinned (View, Section 3) | [`VerifiedImage`], [`ImageFault`] |
//! | Generic rendering: rows in claims order, `null` paths, `template:`, label limits after interpolation, at most 200 items, `security_hint` as given (View, Section 2) | [`TransactionView`], [`RenderFault`] |
//! | Selection: each candidate credential takes its first compatible entry (Core, Section 7.4.2) | [`Context::first_match`], [`Selection`] |
//! | T3, T6: the B.3.3.1 hash over the entry as received, one algorithm per credential, `transaction_data_hashes_alg` repeated when the request carried it; `jti`, `response_mode` and `amr` under a TS12 rulebook; SD-JWT VC only | [`Binding::kb_jwt_claims`], [`Amr`] |
//!
//! Every refusal of a request is a [`TransactionDataError`]; every reason an entry does not
//! serve a credential is an [`Incompatibility`].

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
pub use currency::CurrencyCode;
pub use definition::{
    ActionLabel, BaseType, ClaimDefinition, ClaimDisplay, ClaimFault, ClaimIndex, ClaimName,
    Definition, DefinitionError, DefinitionMember, Description, EntryFault, HintEntry, LabelFormat,
    LabelLength, LabelRole, LabelText, LabelsFault, Localizations, Mandatory, OtherUiElement,
    PayloadPath, Prominence, SecurityHint, TextFault, TransactionTitle, UiLabel, UiLabels,
    ValueType, MAX_CLAIMS,
};
pub use entry::Entry;
pub use error::{EntryMember, EntryPosition, EntryRefusal, TransactionDataError};
pub use fetched::{FetchFault, Fetched, Step};
pub use hash::{AlgClaim, HashAlg, HashesAlgFault};
pub use image::{
    Dimensions, ImageFault, ImageFormat, ImageRef, RasterFault, Resource, SvgFault, VerifiedImage,
    MAX_IMAGE_BYTES, MAX_IMAGE_PIXELS,
};
pub use integrity::{Integrity, IntegrityFault};
pub use output::{Binding, Jti, KbJwtInputs};
pub use payload::{
    CurrencyAmount, Frequency, IsoDateTime, IsoTime, Location, NumberText, PayloadFault,
    PayloadText, Scalar, Step as LocationStep, Typed, ValueFault,
};
pub use projection::{Projected, ProjectedClaim, Unmatched};
pub use render::{RenderFault, TemplateFault, MAX_ITEMS};
pub use select::{Context, Exclusion, Incompatibility, Selection, Taken};
pub use sets::{SetPosition, SetsFault};
pub use sources::{
    AdHocMetadata, Configuration, ConfigurationError, ConfigurationMember, Configured,
    ConfiguredFault, ConfiguredType, CredentialMetadataFault, JwkFault, JwsFault, KeySetFault,
    MetadataClaim, Rulebook, SignedFault, SourceKind, Ts12Fault, Ts12Member,
};
pub use ts12::read::{MemberPath, Ts12PayloadFault};
pub use type_id::{EmptyTypeId, Ts12Type, TypeFamily, TypeId};
pub use view::{Row, RowValue, ShownLabel, TransactionView, UnsignedWarning};

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
