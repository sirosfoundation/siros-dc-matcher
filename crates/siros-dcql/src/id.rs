//! Credential Query identifiers (§6.1).

use core::fmt;
use core::ops::Deref;

use serde::{Deserialize, Serialize};

/// A Credential Query `id`: "a non-empty string consisting of alphanumeric, underscore (`_`), or
/// hyphen (`-`) characters" (§6.1), alphanumeric read as ASCII. The response keys the
/// presentations by it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct QueryId(String);

/// Why a text is no Credential Query `id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum QueryIdError {
    /// The text is empty.
    #[error("a credential query id is empty (§6.1)")]
    Empty,
    /// The text holds this character, which is not an ASCII letter, a digit, `_` or `-`.
    #[error("a credential query id holds {0:?} (§6.1)")]
    Character(char),
}

impl QueryIdError {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Empty => "query_id_empty",
            Self::Character(_) => "query_id_character",
        }
    }
}

impl QueryId {
    /// The Credential Query `id` `text`.
    ///
    /// # Errors
    ///
    /// [`QueryIdError`]: an empty text, or one with another character.
    pub fn parse(text: &str) -> Result<Self, QueryIdError> {
        let allowed = |c: &char| c.is_ascii_alphanumeric() || *c == '_' || *c == '-';
        match text.chars().find(|c| !allowed(c)) {
            Some(c) => Err(QueryIdError::Character(c)),
            None if text.is_empty() => Err(QueryIdError::Empty),
            None => Ok(Self(text.to_owned())),
        }
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for QueryId {
    type Error = QueryIdError;

    fn try_from(text: String) -> Result<Self, QueryIdError> {
        Self::parse(&text)
    }
}

impl From<QueryId> for String {
    fn from(id: QueryId) -> Self {
        id.0
    }
}

impl Deref for QueryId {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for QueryId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for QueryId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for QueryId {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl fmt::Display for QueryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
