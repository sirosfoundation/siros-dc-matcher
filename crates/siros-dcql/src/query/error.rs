//! Why a document is no DCQL query (§6), each with a stable code and its cause.

use core::fmt;

use crate::authority::TrustedAuthorityError;
use crate::id::{ClaimId, ClaimIdError, QueryId, QueryIdError};
use crate::path::ClaimPathError;

crate::position!(
    /// The position of an entry in an array of the query, from 0.
    Position
);

/// A member of a Credential Query (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialMember {
    /// `id`.
    Id,
    /// `format`.
    Format,
    /// `multiple`.
    Multiple,
    /// `meta`.
    Meta,
    /// `require_cryptographic_holder_binding`.
    HolderBinding,
    /// `claims`.
    Claims,
    /// `claim_sets`.
    ClaimSets,
}

/// A member of a claims query (§6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimMember {
    /// `id`.
    Id,
    /// `path`.
    Path,
    /// `values`.
    Values,
}

/// A member of a credential set query (§6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetMember {
    /// `options`.
    Options,
    /// `required`.
    Required,
}

/// Where in a DCQL query a member breaks its form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Member {
    /// The query itself.
    Query,
    /// `credentials`.
    Credentials,
    /// The Credential Query at this position.
    Credential(Position),
    /// A member of the Credential Query at this position.
    CredentialMember(Position, CredentialMember),
    /// The claims query at the second position of the Credential Query at the first.
    Claim(Position, Position),
    /// A member of that claims query.
    ClaimMember(Position, Position, ClaimMember),
    /// `credential_sets`.
    CredentialSets,
    /// The credential set query at this position.
    CredentialSet(Position),
    /// A member of the credential set query at this position.
    CredentialSetMember(Position, SetMember),
}

/// What breaks the form of a member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormFault {
    /// It is absent.
    Absent,
    /// It has another JSON type than §6 gives it.
    WrongType,
    /// It is an empty array.
    Empty,
    /// The entry at this position has another JSON type than §6 gives it.
    Entry(Position),
}

/// Why a JSON value is no usable DCQL query.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QueryError {
    /// A member breaks the form §6 gives it.
    Form {
        /// The member.
        member: Member,
        /// What breaks its form.
        fault: FormFault,
    },
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
    /// Two credential queries share this `id`, which §6.1 requires to "be unique across all
    /// Credential Query objects".
    DuplicateCredentialId(QueryId),
    /// Two claims queries within one credential query share this `id`, which §6.3 requires to be
    /// unique "within the particular claims array".
    DuplicateClaimId {
        /// The `id` of the credential query holding the duplicate.
        credential: QueryId,
        /// The duplicated claims query `id`.
        claim: ClaimId,
    },
    /// The `path` of a claims query is no claims path pointer (§7).
    ClaimPath {
        /// The `id` of the credential query holding it.
        credential: QueryId,
        /// The claims query's position.
        claim: Position,
        /// Why.
        error: ClaimPathError,
    },
    /// A `claim_sets` option names this id, which no claims query of the credential query has
    /// (§6.1).
    UnknownClaimId {
        /// The `id` of the credential query.
        credential: QueryId,
        /// The id the option names.
        claim: ClaimId,
    },
    /// The Credential Query of this `id` has `claim_sets` and no claims: "`claim_sets` MUST NOT
    /// be present if `claims` is absent" (§6.4.1).
    ClaimSetsWithoutClaims(QueryId),
    /// A `credential_sets` option names this id, which no Credential Query has (§6.2).
    UnknownCredentialId(QueryId),
    /// A claims query of an `mso_mdoc` Credential Query has a `path` other than a namespace and
    /// an element identifier, two strings (§7.2.1).
    MdocPath {
        /// The `id` of the credential query.
        credential: QueryId,
        /// The claims query's position.
        claim: Position,
    },
}

impl QueryError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Form { .. } => "dcql_malformed",
            Self::Id(error) => error.code(),
            Self::ClaimId { error, .. } => error.code(),
            Self::TrustedAuthorities { error, .. } => error.code(),
            Self::ClaimPath { error, .. } => error.code(),
            Self::DuplicateCredentialId(_) => "query_id_not_unique",
            Self::DuplicateClaimId { .. } => "claim_id_not_unique",
            Self::UnknownClaimId { .. } => "claim_id_unknown",
            Self::ClaimSetsWithoutClaims(_) => "claim_sets_without_claims",
            Self::UnknownCredentialId(_) => "query_id_unknown",
            Self::MdocPath { .. } => "mdoc_path_malformed",
        }
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Form { member, fault } => write!(f, "{}: {member:?} {fault:?}", self.code()),
            Self::Id(_) => f.write_str(self.code()),
            Self::DuplicateCredentialId(credential)
            | Self::UnknownCredentialId(credential)
            | Self::ClaimSetsWithoutClaims(credential)
            | Self::ClaimId { credential, .. }
            | Self::TrustedAuthorities { credential, .. }
            | Self::ClaimPath { credential, .. }
            | Self::DuplicateClaimId { credential, .. }
            | Self::UnknownClaimId { credential, .. }
            | Self::MdocPath { credential, .. } => write!(f, "{}: {credential}", self.code()),
        }
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Id(e) => Some(e),
            Self::ClaimId { error, .. } => Some(error),
            Self::TrustedAuthorities { error, .. } => Some(error),
            Self::ClaimPath { error, .. } => Some(error),
            Self::Form { .. }
            | Self::DuplicateCredentialId(_)
            | Self::DuplicateClaimId { .. }
            | Self::UnknownClaimId { .. }
            | Self::ClaimSetsWithoutClaims(_)
            | Self::UnknownCredentialId(_)
            | Self::MdocPath { .. } => None,
        }
    }
}

/// Why JSON text is no usable DCQL query.
#[derive(Debug)]
pub enum QueryTextError {
    /// The text is no JSON.
    Json(serde_json::Error),
    /// The JSON value is no usable DCQL query.
    Query(QueryError),
}

impl QueryTextError {
    /// A stable identifier: `dcql_malformed` for text that is no JSON, else the query's.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Json(_) => "dcql_malformed",
            Self::Query(error) => error.code(),
        }
    }
}

impl fmt::Display for QueryTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "{}: {e}", self.code()),
            Self::Query(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for QueryTextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Query(e) => Some(e),
        }
    }
}
