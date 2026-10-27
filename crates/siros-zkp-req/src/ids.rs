//! The identifiers and positions of a `zkp_req` query and presentation.

use std::borrow::Cow;
use std::fmt;

use siros_dcql::{QueryId, QueryIdError};

/// Declares an identifier a Verifier or a system rulebook writes, of any text: its role is its
/// type. A constant of the rulebook is a `from_static`.
macro_rules! identifier {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            /// The identifier `text`.
            #[must_use]
            pub fn new(text: &str) -> Self {
                Self(Cow::Owned(text.to_owned()))
            }

            /// The identifier `text`, a constant.
            #[must_use]
            pub const fn from_static(text: &'static str) -> Self {
                Self(Cow::Borrowed(text))
            }

            /// The identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

identifier!(
    /// A system identifier (Section 1.2): an entry of `system_id_values`, or a presentation's
    /// `system_id`.
    SystemId
);

identifier!(
    /// A proof backend identifier (Section 1.2): an entry of `proof_backend_values`, or a
    /// presentation's `proof_backend`.
    ProofBackend
);

identifier!(
    /// A W3C credential type a query names in `meta.type_values` (OpenID4VP 1.0, B.1.1).
    W3cType
);

identifier!(
    /// A key of a presentation's `results`, as sent: the Verifier compares it with the option's
    /// `return` handles (Section 4.1, step 4).
    ResultKey
);

impl From<&ReturnHandle> for ResultKey {
    fn from(handle: &ReturnHandle) -> Self {
        Self::new(handle.as_str())
    }
}

identifier!(
    /// A key of `Proof.inputs`, as sent: the system rulebook names the inputs.
    InputName
);

/// A `fn_id` (Section 2): a non-empty string naming a function of the catalogue of the
/// credential's type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FnId(String);

/// Why a text is no `fn_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FnIdError {
    /// The text is empty.
    Empty,
}

impl FnId {
    /// The `fn_id` `text`.
    ///
    /// # Errors
    ///
    /// [`FnIdError::Empty`] for an empty text.
    pub fn parse(text: &str) -> Result<Self, FnIdError> {
        if text.is_empty() {
            return Err(FnIdError::Empty);
        }
        Ok(Self(text.to_owned()))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A `return` handle (Section 2): a non-empty string of the identifier alphabet of OpenID4VP
/// 1.0, Section 6.1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReturnHandle(String);

/// Why a text is no `return` handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReturnHandleError {
    /// The text is empty.
    Empty,
    /// The text holds this character, which is not an ASCII letter, a digit, `_` or `-`.
    Character(char),
}

impl ReturnHandle {
    /// The handle `text`.
    ///
    /// # Errors
    ///
    /// [`ReturnHandleError`]: an empty text, or one with another character.
    pub fn parse(text: &str) -> Result<Self, ReturnHandleError> {
        match QueryId::parse(text) {
            Ok(id) => Ok(Self(id.into())),
            Err(QueryIdError::Empty) => Err(ReturnHandleError::Empty),
            Err(QueryIdError::Character(c)) => Err(ReturnHandleError::Character(c)),
        }
    }

    /// The handle's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Declares a position in one list of a `zkp_req` query or presentation: a number from 0.
macro_rules! position {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value`.
            #[must_use]
            pub const fn new(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            #[must_use]
            pub const fn value(self) -> usize {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

position!(
    /// The index of an item in `_req` (Section 2).
    ItemIndex
);

position!(
    /// The index of an option in `_req_sets` (Section 2.1), which a presentation carries as
    /// `req_set`.
    ReqSetIndex
);

impl ReqSetIndex {
    /// The index as CBOR carries it.
    #[must_use]
    pub fn as_u64(self) -> u64 {
        // usize has at most 64 bits on every target Rust supports.
        self.0 as u64
    }
}

position!(
    /// The position of a presentation in a query's `vp_token` entry (Section 6.1).
    PresentationIndex
);

position!(
    /// The position of an entry in a JSON array of a request.
    ArrayIndex
);
