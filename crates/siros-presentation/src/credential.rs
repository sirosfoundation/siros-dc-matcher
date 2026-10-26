//! The credential the matching reads (K2).

use serde_json::Value;
use siros_credential::{Format, Instance, UsableCredential};
use siros_dcql::{PathComponent, PathError};

/// A credential as the matching reads it: a usable credential of the wallet (C4), or a credential
/// of the picker's registration projection.
pub trait MatchCredential: Instance {
    /// The format.
    fn format(&self) -> Format;

    /// The type: the SD-JWT VC's `vct`, or the mdoc's `docType`.
    fn credential_type(&self) -> &str;

    /// Whether a presentation of the credential proves holder binding.
    fn key_holding(&self) -> KeyHolding;

    /// The values of the claims `path` selects, as JSON, for the comparison with `values`
    /// (OpenID4VP 1.0, Section 6.3).
    ///
    /// # Errors
    ///
    /// [`PathError`] when the pointer does not fit the credential or selects nothing.
    fn claim_values(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError>;
}

/// Whether the wallet holds the key a credential is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyHolding {
    /// The credential is bound to a key the wallet holds: a presentation proves holder binding.
    Held,
    /// The credential is bound to no key, or to one the wallet does not hold.
    NotHeld,
}

impl MatchCredential for UsableCredential<'_> {
    fn format(&self) -> Format {
        self.credential().format()
    }

    fn credential_type(&self) -> &str {
        self.credential().credential_type()
    }

    /// Held for an SD-JWT VC with a P-256 `cnf.jwk`, or an mdoc, whose entry names its key pair.
    fn key_holding(&self) -> KeyHolding {
        let credential = self.credential();
        match (credential.key_id(), credential.holder_key()) {
            (Some(_), Ok(_)) => KeyHolding::Held,
            _ => KeyHolding::NotHeld,
        }
    }

    fn claim_values(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError> {
        siros_dcql::Credential::claim(self.credential(), path)
    }
}
