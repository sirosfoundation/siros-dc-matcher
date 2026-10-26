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

    /// Whether a presentation of the credential proves holder binding: the credential is bound
    /// to a key, and the wallet holds that key.
    fn holds_key(&self) -> bool;

    /// The values of the claims `path` selects, as JSON, for the comparison with `values`
    /// (OpenID4VP 1.0, Section 6.3).
    ///
    /// # Errors
    ///
    /// [`PathError`] when the pointer does not fit the credential or selects nothing.
    fn claim_values(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError>;
}

impl MatchCredential for UsableCredential<'_> {
    fn format(&self) -> Format {
        self.credential().format()
    }

    fn credential_type(&self) -> &str {
        self.credential().credential_type()
    }

    /// An SD-JWT VC with a P-256 `cnf.jwk`, or an mdoc, whose entry names its key pair.
    fn holds_key(&self) -> bool {
        let credential = self.credential();
        credential.key_id().is_some() && credential.holder_key().is_some()
    }

    fn claim_values(&self, path: &[PathComponent]) -> Result<Vec<Value>, PathError> {
        siros_dcql::Credential::claim(self.credential(), path)
    }
}
