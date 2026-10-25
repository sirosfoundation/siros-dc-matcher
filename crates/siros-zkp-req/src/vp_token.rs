//! Reading the presentations of one query from a JSON `vp_token` (`zkp_req`, Section 6.1;
//! OpenID4VP 1.0, Section 8.1).

use std::fmt;

use serde::de::{Deserializer, MapAccess, Visitor};
use serde_json::Value;

use crate::base64url;

/// Why a `vp_token` gives no presentations for a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VpTokenError {
    /// The text is not a JSON object.
    NotObject,
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
        index: usize,
    },
    /// A presentation is not base64url without padding (RFC 4648, Section 5).
    NotBase64url {
        /// Its position in the entry.
        index: usize,
    },
}

impl VpTokenError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotObject => "response_not_object",
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

impl std::error::Error for VpTokenError {}

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
    query_id: &str,
    multiple: bool,
) -> Result<Vec<Vec<u8>>, VpTokenError> {
    let mut deserializer = serde_json::Deserializer::from_str(vp_token);
    let Members(members) = deserializer
        .deserialize_map(MembersVisitor)
        .map_err(|_| VpTokenError::NotObject)?;
    deserializer.end().map_err(|_| VpTokenError::NotObject)?;
    let repeated = members
        .iter()
        .enumerate()
        .any(|(i, (name, _))| members.iter().skip(i + 1).any(|(other, _)| other == name));
    if repeated {
        return Err(VpTokenError::DuplicateMember);
    }
    let entry = members
        .iter()
        .find(|(name, _)| name == query_id)
        .map(|(_, value)| value)
        .ok_or(VpTokenError::QueryIdMissing)?;
    let list = entry.as_array().ok_or(VpTokenError::NotArray)?;
    match (list.len(), multiple) {
        (0, _) => return Err(VpTokenError::Empty),
        (1, _) | (_, true) => {}
        (_, false) => return Err(VpTokenError::MultipleNotAllowed),
    }
    list.iter()
        .enumerate()
        .map(|(index, p)| {
            let text = p.as_str().ok_or(VpTokenError::NotString { index })?;
            base64url::decode(text).ok_or(VpTokenError::NotBase64url { index })
        })
        .collect()
}
