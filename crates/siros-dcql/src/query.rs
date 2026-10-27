//! The DCQL query model — OpenID4VP 1.0 §6.
//!
//! A query is constructed only by parsing ([`DcqlQuery::from_json`], [`DcqlQuery::parse`] or
//! its `Deserialize`), which enforces the identifier syntax and uniqueness of §6.1 and §6.3 and
//! the structure of `trusted_authorities` (§6.1.1). "Implementations MUST ignore any unknown
//! properties" (§6), and so does the parse.

mod unchecked;

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::authority::{TrustedAuthorities, TrustedAuthorityError};
use crate::id::{ClaimId, ClaimIdError, QueryId, QueryIdError};
use crate::meta::CredentialFormat;
use crate::path::PathComponent;

/// A complete DCQL query (§6).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "unchecked::Unchecked")]
pub struct DcqlQuery {
    credentials: Vec<CredentialQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One requested credential (§6.1), with the defaults §6.1 states.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialQuery {
    id: QueryId,
    format: CredentialFormat,
    #[serde(default = "Multiplicity::stated")]
    multiple: Multiplicity,
    #[serde(default)]
    meta: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trusted_authorities: Option<TrustedAuthorities>,
    #[serde(
        rename = "require_cryptographic_holder_binding",
        default = "HolderBinding::stated",
        skip_serializing_if = "HolderBinding::is_stated"
    )]
    holder_binding: HolderBinding,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    claims: Vec<ClaimsQuery>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    claim_sets: Option<Vec<Vec<ClaimId>>>,
}

/// One requested claim (§6.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClaimsQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id: Option<ClaimId>,
    path: Vec<PathComponent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    values: Option<Vec<Value>>,
}

/// A constraint on which combinations of credentials satisfy the request (§6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialSetQuery {
    options: Vec<Vec<QueryId>>,
    #[serde(default = "SetRequirement::stated")]
    required: SetRequirement,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purpose: Option<Value>,
}

/// Whether a Credential Query accepts several credentials (§6.1 `multiple`, `false` when
/// absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Multiplicity {
    /// One credential answers the query.
    One,
    /// "multiple Credentials can be returned for this Credential Query".
    Several,
}

/// Whether a Credential Query requires cryptographic holder binding (§6.1
/// `require_cryptographic_holder_binding`, `true` when absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HolderBinding {
    /// The presentation proves possession of the credential's key.
    Required,
    /// The presentation may go without a proof of possession.
    Optional,
}

/// Whether a credential set must be satisfied (§6.2 `required`, `true` when absent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetRequirement {
    /// The request is satisfied only with one of the set's options.
    Required,
    /// The Wallet may add one of the set's options.
    Optional,
}

impl HolderBinding {
    /// Whether the member takes the value §6.1 states for its absence, which the serialisation
    /// leaves out.
    fn is_stated(&self) -> bool {
        *self == Self::stated()
    }
}

/// Declares the wire form of a flag: the boolean of its member, with `$true` for `true` and
/// `$false` for `false`, and `$stated` when the member is absent.
macro_rules! flag {
    ($name:ident, $true:ident, $false:ident, $stated:ident) => {
        impl $name {
            /// The value §6.1 or §6.2 states for an absent member.
            fn stated() -> Self {
                Self::$stated
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bool(*self == Self::$true)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Ok(if bool::deserialize(deserializer)? {
                    Self::$true
                } else {
                    Self::$false
                })
            }
        }
    };
}

flag!(Multiplicity, Several, One, One);
flag!(HolderBinding, Required, Optional, Required);
flag!(SetRequirement, Required, Optional, Required);

/// Why a document is not a usable DCQL query.
///
/// §6 instructs implementations to "ignore any unknown properties", and the parse goes further
/// in the same spirit: a query is refused only when what the Verifier wants cannot be
/// determined. A duplicated `id` makes a reference ambiguous and is refused; a
/// `credential_sets` option naming a query that does not exist is an option the wallet cannot
/// satisfy, and is kept.
#[derive(Debug)]
pub enum QueryError {
    /// Not well-formed JSON, or not shaped like a DCQL query.
    Json(serde_json::Error),
    /// A credential query `id`, or one a `credential_sets` option names, breaks §6.1.
    Id(QueryIdError),
    /// A claims query `id`, or one a `claim_sets` option names, breaks §6.3.
    ClaimId {
        /// The `id` of the credential query holding it.
        credential: QueryId,
        /// Why.
        error: ClaimIdError,
    },
    /// `trusted_authorities` breaks §6.1.1.
    TrustedAuthorities {
        /// The `id` of the credential query holding it.
        credential: QueryId,
        /// Why.
        error: TrustedAuthorityError,
    },
    /// Two credential queries share this `id`. §6.1 requires it to "be unique across all
    /// Credential Query objects": a reference from `credential_sets` to a duplicated id names
    /// two different requests, and answering the first silently drops the second.
    DuplicateCredentialId(QueryId),
    /// Two claims queries within one credential query share this `id`. §6.3 requires
    /// uniqueness "within the particular claims array", for the same reason one level down:
    /// `claim_sets` refers to claims by id.
    DuplicateClaimId {
        /// The `id` of the credential query holding the duplicate.
        credential: QueryId,
        /// The duplicated claims query `id`.
        claim: ClaimId,
    },
}

impl QueryError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "dcql_malformed",
            Self::Id(error) => error.code(),
            Self::ClaimId { error, .. } => error.code(),
            Self::TrustedAuthorities { error, .. } => error.code(),
            Self::DuplicateCredentialId(_) => "query_id_not_unique",
            Self::DuplicateClaimId { .. } => "claim_id_not_unique",
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "{}: {e}", self.code()),
            Self::Id(_) => f.write_str(self.code()),
            Self::DuplicateCredentialId(credential)
            | Self::ClaimId { credential, .. }
            | Self::TrustedAuthorities { credential, .. }
            | Self::DuplicateClaimId { credential, .. } => {
                write!(f, "{}: {credential}", self.code())
            }
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Id(e) => Some(e),
            Self::ClaimId { error, .. } => Some(error),
            Self::TrustedAuthorities { error, .. } => Some(error),
            Self::DuplicateCredentialId(_) | Self::DuplicateClaimId { .. } => None,
        }
    }
}

impl From<serde_json::Error> for QueryError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl DcqlQuery {
    /// The DCQL query of the JSON text `json`.
    ///
    /// # Errors
    ///
    /// [`QueryError`]: the document is not a well-formed DCQL query, or its identifiers or
    /// `trusted_authorities` break §6.1, §6.1.1 or §6.3. Unknown properties are not an error
    /// (§6).
    pub fn from_json(json: &str) -> Result<Self, QueryError> {
        Self::parse(&serde_json::from_str(json)?)
    }

    /// The DCQL query of the JSON value `document`, as [`Self::from_json`] reads text.
    ///
    /// # Errors
    ///
    /// [`QueryError`], as for [`Self::from_json`].
    pub fn parse(document: &Value) -> Result<Self, QueryError> {
        if let Some(error) = unchecked::typed_error(document) {
            return Err(error);
        }
        Self::try_from(unchecked::Unchecked::deserialize(document)?)
    }

    /// The requested credentials (§6.1), in the Verifier's order.
    #[must_use]
    pub fn credentials(&self) -> &[CredentialQuery] {
        &self.credentials
    }

    /// The constraints on which combinations to return (§6.2).
    ///
    /// Absent means something specific: "If `credential_sets` is not provided, the Verifier
    /// requests presentations for all Credentials in `credentials`" (§6.4).
    #[must_use]
    pub fn credential_sets(&self) -> Option<&[CredentialSetQuery]> {
        self.credential_sets.as_deref()
    }

    /// The credential query with the given id.
    #[must_use]
    pub fn credential(&self, id: &str) -> Option<&CredentialQuery> {
        self.credentials.iter().find(|c| c.id == *id)
    }
}

impl CredentialQuery {
    /// Identifies this query in the response and in `credential_sets`.
    #[must_use]
    pub fn id(&self) -> &QueryId {
        &self.id
    }

    /// The requested credential format.
    #[must_use]
    pub fn format(&self) -> &CredentialFormat {
        &self.format
    }

    /// Whether more than one credential may be returned for this query.
    #[must_use]
    pub fn multiplicity(&self) -> Multiplicity {
        self.multiple
    }

    /// Format-specific constraints on metadata and validity.
    ///
    /// The spec marks `meta` REQUIRED, but "If empty, no specific constraints are placed"
    /// (§6.1), so a missing `meta` reads as an empty one.
    #[must_use]
    pub fn meta(&self) -> &Map<String, Value> {
        &self.meta
    }

    /// Authorities whose issuance the Verifier accepts (§6.1.1), when it names any.
    #[must_use]
    pub fn trusted_authorities(&self) -> Option<&TrustedAuthorities> {
        self.trusted_authorities.as_ref()
    }

    /// Whether cryptographic holder binding is required.
    #[must_use]
    pub fn holder_binding(&self) -> HolderBinding {
        self.holder_binding
    }

    /// Claims requested from this credential (§6.3).
    #[must_use]
    pub fn claims(&self) -> &[ClaimsQuery] {
        &self.claims
    }

    /// Alternative combinations of [`Self::claims`], by their ids (§6.1), in the Verifier's
    /// order of preference.
    #[must_use]
    pub fn claim_sets(&self) -> Option<&[Vec<ClaimId>]> {
        self.claim_sets.as_deref()
    }

    /// The claims query with the given id. The parse refuses duplicated claim ids, so the id
    /// names at most one.
    #[must_use]
    pub fn claim(&self, id: &str) -> Option<&ClaimsQuery> {
        self.claims
            .iter()
            .find(|c| c.id.as_ref().is_some_and(|own| *own == *id))
    }
}

impl ClaimsQuery {
    /// Identifies this claim. "REQUIRED if `claim_sets` is present in the Credential Query;
    /// OPTIONAL otherwise" (§6.3).
    #[must_use]
    pub fn id(&self) -> Option<&ClaimId> {
        self.id.as_ref()
    }

    /// The claims path pointer to the claim (§7).
    #[must_use]
    pub fn path(&self) -> &[PathComponent] {
        &self.path
    }

    /// Expected values. "the Wallet SHOULD return the claim only if the type and value of the
    /// claim both match exactly for at least one of the elements in the array" (§6.3).
    #[must_use]
    pub fn values(&self) -> Option<&[Value]> {
        self.values.as_deref()
    }
}

impl CredentialSetQuery {
    /// The options: each a set of Credential Query ids that together satisfy this use case.
    #[must_use]
    pub fn options(&self) -> &[Vec<QueryId>] {
        &self.options
    }

    /// Whether this set must be satisfied.
    #[must_use]
    pub fn requirement(&self) -> SetRequirement {
        self.required
    }

    /// Why the Verifier wants this combination, for showing to the user (§6.2): a string, an
    /// integer or an object.
    #[must_use]
    pub fn purpose(&self) -> Option<&Value> {
        self.purpose.as_ref()
    }
}
