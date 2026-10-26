//! The identifiers and positions the plan, its view and the selection carry.

use std::fmt;

/// A Credential Query `id`: a non-empty string of ASCII letters, digits, `_` and `-`
/// (OpenID4VP 1.0, Section 6.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryId(String);

/// Why a text is no Credential Query `id`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QueryIdError {
    /// The text is empty.
    Empty,
    /// The text holds a character other than an ASCII letter, a digit, `_` or `-`.
    Character(String),
}

impl QueryIdError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "query_id_empty",
            Self::Character(_) => "query_id_character",
        }
    }
}

impl fmt::Display for QueryIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for QueryIdError {}

impl QueryId {
    /// The Credential Query `id` `text`.
    ///
    /// # Errors
    ///
    /// [`QueryIdError`]: an empty text, or one with another character.
    pub fn parse(text: &str) -> Result<Self, QueryIdError> {
        if text.is_empty() {
            return Err(QueryIdError::Empty);
        }
        let allowed = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
        if !text.chars().all(allowed) {
            return Err(QueryIdError::Character(text.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for QueryId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl fmt::Display for QueryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Declares a position among the items of one list of the plan: constructed by the crate as it
/// enumerates the list, read as a number.
macro_rules! position {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value` in its list.
            pub(crate) fn at(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            pub fn value(self) -> usize {
                self.0
            }
        }
    };
}

#[cfg(feature = "wallet")]
pub(crate) use position;

/// Declares a position the host names in a selection: any number, which the plan judges.
macro_rules! chosen {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value`, as the host names it.
            pub fn new(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            pub fn value(self) -> usize {
                self.0
            }
        }
    };
}

position!(
    /// The position of a Credential Query in the DCQL query's `credentials`.
    QueryIndex
);

position!(
    /// The position of a candidate among the candidates of its Credential Query.
    CandidateIndex
);

position!(
    /// The position of a credential set in the DCQL query's `credential_sets`.
    SetIndex
);

position!(
    /// The position of an option among the options of a `zkp_req` query.
    OptionIndex
);

chosen!(
    /// The position of an offer in the consent view.
    OfferIndex
);

chosen!(
    /// The position of an addition among the additions of an offer in the consent view.
    AdditionIndex
);

chosen!(
    /// The position of a credential among the credentials of a member in the consent view.
    Position
);
