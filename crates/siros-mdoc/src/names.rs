//! The names and identifiers of an mdoc's items (ISO/IEC 18013-5, 8.3.2.1.2.2 and 9.1.2.4).

use std::fmt;

/// Declares a text an mdoc names its items by.
macro_rules! name {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// The name `text`.
            #[must_use]
            pub fn new(text: &str) -> Self {
                Self(text.to_owned())
            }

            /// The name.
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

        impl std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

name!(
    /// `NameSpace`: a namespace of data elements.
    NameSpace
);

name!(
    /// `DataElementIdentifier`: an element's identifier within its namespace.
    ElementIdentifier
);

/// `DigestID`: the number `valueDigests` lists an item's digest under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DigestId(u64);

impl DigestId {
    /// The identifier `value`.
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The number.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0
    }
}
