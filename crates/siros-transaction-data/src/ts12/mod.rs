//! The four transaction data types of EC TS12 v1.0.1 (Section 4.3).
//!
//! Each payload parses into the typed value its schema describes (`docs/technical-specifications/api/`
//! of the TS12 repository): `additionalProperties: false` at the top, open nested objects, and
//! `format` an annotation only, as JSON Schema 2020-12 has it.

mod display;
mod payloads;
mod payment;

use siros_credential::Format;
use siros_display::Locale;

use crate::binding::{Binding, KbJwtClaim};
use crate::error::TransactionDataError;
use crate::hash::{Accepted, HASHES_ALG};
use crate::json::{self, Fields, Json};
use crate::kind::TransactionType;
use crate::labels::DisplayMetadata;
use crate::metadata::TypeMetadata;
use crate::view::TransactionView;

pub(crate) use display::Leaves;
pub(crate) use payloads::{AccountAccess, Emandate, LoginRisk};
pub(crate) use payment::Payment;

/// The `category` that makes an SD-JWT VC an SCA Attestation (Section 3).
const SCA_CATEGORY: &str = "urn:eu:europa:ec:eudi:sua:sca";

/// The KB-JWT claims every TS12 type requires besides its hashes (Section 3.6).
const CLAIMS: [KbJwtClaim; 3] = [KbJwtClaim::Jti, KbJwtClaim::ResponseMode, KbJwtClaim::Amr];

/// The `payload` of one TS12 type.
pub(crate) trait Payload: Sized + 'static {
    /// The `type` value.
    const TYPE: &'static str;

    /// The payload of the members of the `payload` object.
    fn parse(fields: Fields) -> Result<Self, TransactionDataError>;

    /// Its leaf parameters, in the order of its schema (Section 3.3.1).
    fn leaves(&self, leaves: &mut Leaves);
}

/// An entry of a TS12 type: the algorithms of its hash and its payload (Section 4.2).
pub(crate) struct Ts12<P> {
    accepted: Accepted,
    payload: P,
}

impl<P: Payload> Ts12<P> {
    /// The entry of the members besides `type` and `credential_ids`: `transaction_data_hashes_alg`
    /// and `payload`, both required (Section 4.2).
    pub(crate) fn parse(
        mut fields: Fields,
    ) -> Result<Box<dyn TransactionType>, TransactionDataError> {
        let accepted = Accepted::parse(Some(fields.require(HASHES_ALG, HASHES_ALG)?))?;
        let payload = P::parse(json::object(
            fields.require("payload", "payload")?,
            "payload",
        )?)?;
        fields.finish()?;
        Ok(Box::new(Self { accepted, payload }))
    }
}

impl<P: Payload> TransactionType for Ts12<P> {
    fn identifier(&self) -> &'static str {
        P::TYPE
    }

    /// SD-JWT VC only (Section 1.2).
    fn format(&self) -> Format {
        Format::SdJwtVc
    }

    /// An SCA Attestation whose type metadata lists the type (Sections 3 and 3.2).
    fn authorizes(&self, metadata: &TypeMetadata<'_>) -> bool {
        metadata.category() == Some(SCA_CATEGORY) && metadata.display_metadata(P::TYPE).is_some()
    }

    /// The B.3.3.1 hashes, and `jti`, `response_mode` and `amr` (Section 3.6).
    fn binding(&self) -> Binding<'_> {
        Binding {
            hashes: &self.accepted,
            claims: &CLAIMS,
        }
    }

    fn display(
        &self,
        metadata: &DisplayMetadata,
        preferences: &[Locale],
    ) -> Result<TransactionView, TransactionDataError> {
        let mut leaves = Leaves::payload();
        self.payload.leaves(&mut leaves);
        display::view(P::TYPE, leaves, metadata, preferences)
    }
}

/// `transaction_id`: 1 to 36 characters, required in every payload (Section 4.3).
fn transaction_id(fields: &mut Fields) -> Result<String, TransactionDataError> {
    bounded(
        fields.require("transaction_id", "transaction_id")?,
        "transaction_id",
        1,
        36,
    )
}

/// `value` as a string of `min` to `max` characters (JSON Schema `minLength`, `maxLength`).
fn bounded(
    value: Json,
    path: &'static str,
    min: usize,
    max: usize,
) -> Result<String, TransactionDataError> {
    let text = json::text(value, path)?;
    if (min..=max).contains(&text.chars().count()) {
        Ok(text)
    } else {
        Err(TransactionDataError::InvalidValue(path))
    }
}
