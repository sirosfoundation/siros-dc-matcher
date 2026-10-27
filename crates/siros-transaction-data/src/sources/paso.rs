//! The signed credential metadata JWT of a PaSO Credential (PaSO Proof Metadata, Sections 4 and
//! 7): fetched through the host from the configuration's `credential_metadata_uri`, verified each
//! time it is loaded (Section 6), its `credential_metadata_uri` claim the URL fetched (Section 8),
//! and read into a definition per transaction data type.

use std::str::Utf8Error;

use siros_credential::Credential;
use siros_oid4vp::{BodyLimit, HttpsUrl, MediaType};

use super::signed::{self, MetadataClaim, SignedFault, Verifier};
use crate::definition::{Definition, DefinitionError};
use crate::fetched::{FetchFault, Step};
use crate::json;
use crate::type_id::TypeId;

/// The `typ` of a signed credential metadata JWT (Section 4).
const TYP: &str = "credential-metadata+jwt";

/// The largest signed credential metadata JWT read.
const MAX_JWT: BodyLimit = BodyLimit::bytes(256 * 1024);

/// Why a credential's signed credential metadata is invalid. The credential is then excluded
/// from PaSO processing (Section 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialMetadataFault {
    /// The host gave no JWT.
    Fetch(FetchFault),
    /// The JWT's bytes are no UTF-8 text.
    NotUtf8(Utf8Error),
    /// The JWT is invalid (Section 7).
    Invalid(SignedFault),
    /// The JWT's `credential_metadata_uri` claim holds this text, which differs from the URL
    /// the JWT was fetched from (Section 8).
    UriMismatch(String),
}

impl CredentialMetadataFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Fetch(fault) => fault.code(),
            Self::NotUtf8(_) => "credential_metadata_not_utf8",
            Self::Invalid(fault) => fault.code(),
            Self::UriMismatch(_) => "credential_metadata_uri_mismatch",
        }
    }
}

siros_codec::display_code!(CredentialMetadataFault);

impl std::error::Error for CredentialMetadataFault {}

/// The transaction data types of a verified signed credential metadata JWT, each with its
/// definition or why the definition breaks Section 3.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CredentialMetadata(Vec<(String, Result<Definition, DefinitionError>)>);

impl CredentialMetadata {
    /// The signed credential metadata of `credential` at `uri`, verified (Section 7); the
    /// fetch of the JWT or of the issuer's key set while the host has not given it.
    pub(crate) fn load(
        uri: &HttpsUrl,
        credential: &Credential,
        verifier: Verifier<'_>,
    ) -> Result<Step<Self>, CredentialMetadataFault> {
        let body = match verifier
            .fetched
            .body(uri, MediaType::JWT, MAX_JWT)
            .map_err(CredentialMetadataFault::Fetch)?
        {
            Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
            Step::Done(body) => body,
        };
        let text = std::str::from_utf8(body).map_err(CredentialMetadataFault::NotUtf8)?;
        let invalid = CredentialMetadataFault::Invalid;
        let mut claims =
            match signed::verify(text.trim(), TYP, credential, verifier).map_err(invalid)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(claims) => claims,
            };
        let served_from = signed::text_claim(&mut claims, MetadataClaim::CredentialMetadataUri)
            .map_err(invalid)?;
        if served_from != uri.as_str() {
            return Err(CredentialMetadataFault::UriMismatch(served_from));
        }
        let member = |claim: MetadataClaim| {
            move |fault| CredentialMetadataFault::Invalid(SignedFault::Claim(claim, fault))
        };
        let mut metadata = claims
            .require(MetadataClaim::CredentialMetadata.as_str())
            .and_then(json::object)
            .map_err(member(MetadataClaim::CredentialMetadata))?;
        let types = metadata
            .require(MetadataClaim::TransactionDataTypes.as_str())
            .and_then(json::object)
            .map_err(member(MetadataClaim::TransactionDataTypes))?;
        Ok(Step::Done(Self(
            types
                .rest()
                .into_iter()
                .map(|(name, value)| (name, Definition::parse(value)))
                .collect(),
        )))
    }

    /// The definition of `type_id`, when the metadata lists the type.
    pub(crate) fn definition(
        &self,
        type_id: &TypeId,
    ) -> Option<&Result<Definition, DefinitionError>> {
        self.0
            .iter()
            .find(|(name, _)| name == type_id.as_str())
            .map(|(_, definition)| definition)
    }
}
