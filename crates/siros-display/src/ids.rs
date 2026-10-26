//! The identifiers that key display metadata.

use std::borrow::Borrow;
use std::fmt;

/// A Credential Issuer Identifier: the `credential_issuer` of OpenID4VCI issuer metadata
/// (OpenID4VCI 1.0, Section 12.2.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IssuerIdentifier(String);

/// A credential configuration identifier: a key of `credential_configurations_supported`
/// (OpenID4VCI 1.0, Section 12.2.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigurationId(String);

/// A verifiable credential type: the `vct` and `extends` of SD-JWT VC Type Metadata (SD-JWT VC,
/// Section 5.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Vct(String);

macro_rules! text_identifier {
    ($name:ident) => {
        impl $name {
            pub(crate) fn new(text: &str) -> Self {
                Self(text.to_owned())
            }

            /// The identifier as the metadata writes it.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        /// Map lookups by the text a credential carries.
        impl Borrow<str> for $name {
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

text_identifier!(IssuerIdentifier);
text_identifier!(ConfigurationId);
text_identifier!(Vct);
