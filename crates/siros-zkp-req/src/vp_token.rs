//! Reading the presentations of one query from a JSON `vp_token` (`zkp_req`, Section 6.1;
//! OpenID4VP 1.0, Section 8.1).

use std::fmt;

use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::Value;

use siros_codec::{base64url, Base64Error};
use siros_dcql::{Multiplicity, QueryId};

use crate::ids::PresentationIndex;

/// Why a `vp_token` gives no presentations for a query.
#[derive(Debug)]
pub enum VpTokenError {
    /// The text is not one JSON object.
    NotObject(serde_json::Error),
    /// The object repeats a member name.
    DuplicateMember,
    /// The object has no entry for the query's `id`.
    QueryIdMissing,
    /// The entry is not an array.
    NotArray,
    /// The entry is an empty array.
    Empty,
    /// The entry holds several presentations and the query does not set `multiple`.
    MultipleNotAllowed,
    /// A presentation is not a string.
    NotString {
        /// Its position in the entry.
        index: PresentationIndex,
    },
    /// A presentation is not base64url without padding (RFC 4648, Section 5).
    NotBase64url {
        /// Its position in the entry.
        index: PresentationIndex,
        /// What breaks the encoding.
        error: Base64Error,
    },
}

impl VpTokenError {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject(_) => "response_not_object",
            Self::DuplicateMember => "duplicate_member",
            Self::QueryIdMissing => "query_id_missing",
            Self::NotArray => "presentations_not_array",
            Self::Empty => "presentations_empty",
            Self::MultipleNotAllowed => "presentations_multiple_not_allowed",
            Self::NotString { .. } => "presentation_not_string",
            Self::NotBase64url { .. } => "presentation_not_base64url",
        }
    }
}

impl fmt::Display for VpTokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for VpTokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotObject(error) => Some(error),
            Self::NotBase64url { error, .. } => Some(error),
            Self::DuplicateMember
            | Self::QueryIdMissing
            | Self::NotArray
            | Self::Empty
            | Self::MultipleNotAllowed
            | Self::NotString { .. } => None,
        }
    }
}

/// The members of a JSON object in their order, repeated names kept.
struct Members(Vec<(String, Value)>);

struct MembersVisitor;

impl<'de> Visitor<'de> for MembersVisitor {
    type Value = Members;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
        let mut members = Vec::new();
        while let Some(entry) = map.next_entry::<String, Value>()? {
            members.push(entry);
        }
        Ok(Members(members))
    }
}

/// The CBOR presentations that answer `query_id` in the JSON `vp_token` text. In JSON, each
/// `ZkpPresentation` is the base64url, without padding, of its CBOR encoding.
///
/// # Errors
///
/// [`VpTokenError`]: the first rule the `vp_token` breaks for this query.
pub fn presentations_of(
    vp_token: &str,
    query_id: &QueryId,
    multiplicity: Multiplicity,
) -> Result<Vec<Vec<u8>>, VpTokenError> {
    let mut deserializer = serde_json::Deserializer::from_str(vp_token);
    let Members(members) = deserializer
        .deserialize_map(MembersVisitor)
        .map_err(VpTokenError::NotObject)?;
    deserializer.end().map_err(VpTokenError::NotObject)?;
    let repeated = members
        .iter()
        .enumerate()
        .any(|(i, (name, _))| members.iter().skip(i + 1).any(|(other, _)| other == name));
    if repeated {
        return Err(VpTokenError::DuplicateMember);
    }
    let entry = members
        .iter()
        .find(|(name, _)| query_id == name)
        .map(|(_, value)| value)
        .ok_or(VpTokenError::QueryIdMissing)?;
    let list = entry.as_array().ok_or(VpTokenError::NotArray)?;
    match (list.len(), multiplicity) {
        (0, _) => return Err(VpTokenError::Empty),
        (1, _) | (_, Multiplicity::Several) => {}
        (_, Multiplicity::One) => return Err(VpTokenError::MultipleNotAllowed),
    }
    list.iter()
        .enumerate()
        .map(|(index, p)| {
            let index = PresentationIndex::new(index);
            let text = p.as_str().ok_or(VpTokenError::NotString { index })?;
            base64url::decode(text).map_err(|error| VpTokenError::NotBase64url { index, error })
        })
        .collect()
}
