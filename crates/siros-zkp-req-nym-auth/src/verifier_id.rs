//! The Verifier's identity, and `verifier_input` and the `sha-256` pseudonym it selects
//! (nym_auth catalogue, `pseudonym`: "Verifier identity" and "Configurations").

use std::fmt;

use sha2::{Digest, Sha256};
use siros_oid4vp::{ClientId, ClientIdPrefix, SemanticIdError, SemanticIdentifier};

use crate::catalogue::{Config, Pseudonym};

/// `verifier_id`: a UTF-8 string naming the Verifier, in the one form its trust framework
/// fixes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerifierId(String);

/// Why the `verifier_id` of the fixed form cannot be obtained. Each makes the query invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifierIdRule {
    /// The form is `semantic` and no semantic identifier comes from an authenticated source.
    SemanticIdMissing,
    /// The form is `semantic` and the authenticated certificate's subject gives no semantics
    /// identifier.
    SemanticId(SemanticIdError),
    /// The form is `x509_san_dns` and the Client Identifier has another prefix.
    ClientIdPrefix,
    /// The form is `x509_san_dns` and the registration certificate names an intermediary.
    Intermediary,
    /// The request carries a registration certificate, which no intake authenticates: the
    /// semantic identifier and the intermediary it names come from no authenticated source.
    RegistrationCertificate,
}

impl VerifierIdRule {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::SemanticIdMissing => "semantic_id_missing",
            Self::SemanticId(e) => e.code(),
            Self::ClientIdPrefix => "client_id_prefix",
            Self::Intermediary => "intermediary",
            Self::RegistrationCertificate => "registration_certificate",
        }
    }
}

impl fmt::Display for VerifierIdRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for VerifierIdRule {}

/// Whether the Verifier's registration certificate names an intermediary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Intermediary {
    /// It names none, or the request carries no registration certificate.
    Absent,
    /// It names one.
    Named,
}

impl VerifierId {
    /// The `semantic` form: `"semantic_id:"` and the end Relying Party's semantics identifier,
    /// from the registration certificate when present, else from the access certificate.
    pub fn semantic(identifier: &SemanticIdentifier) -> Self {
        Self(format!("semantic_id:{}", identifier.as_str()))
    }

    /// The `x509_san_dns` form: the Client Identifier itself, whose prefix gives its DNS name.
    ///
    /// # Errors
    ///
    /// [`VerifierIdRule::ClientIdPrefix`] for another prefix, and
    /// [`VerifierIdRule::Intermediary`] when the registration certificate names an
    /// intermediary.
    pub fn x509_san_dns(
        client_id: &ClientId,
        intermediary: Intermediary,
    ) -> Result<Self, VerifierIdRule> {
        if client_id.prefix() != ClientIdPrefix::X509SanDns {
            return Err(VerifierIdRule::ClientIdPrefix);
        }
        if intermediary == Intermediary::Named {
            return Err(VerifierIdRule::Intermediary);
        }
        Ok(Self(client_id.as_str().to_owned()))
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The form of `verifier_id` the Verifier's trust framework fixes (nym_auth catalogue,
/// "Verifier identity").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerifierIdForm {
    /// `semantic`: `"semantic_id:"` and the end Relying Party's semantic identifier.
    Semantic,
    /// `x509_san_dns`: the Client Identifier.
    X509SanDns,
}

/// `verifier_input` of a `pseudonym` (the table of "Configurations").
pub fn verifier_input(pseudonym: &Pseudonym, verifier_id: &VerifierId) -> [u8; 32] {
    let id = sha256(verifier_id.as_str().as_bytes());
    match &pseudonym.config {
        Config::UserManagedPseudonymXsiteSsc => [0; 32],
        Config::AccountRecoverySsc { verifier_context } => {
            sha256(&[id, sha256(verifier_context.as_bytes())].concat())
        }
        Config::KnownOffenderMatchingSsc | Config::KnownOffenderMatchingPsc => id,
    }
}

/// `pseudonym = SHA256(DST ‖ seed ‖ prover_input ‖ verifier_input)` with
/// `DST = UTF-8("nym_auth/v1/<config>")`, the `sha-256` PRF of `ver` 1.
pub fn pseudonym_sha256(
    config: &Config,
    seed: &[u8; 16],
    prover_input: &[u8; 32],
    verifier_input: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"nym_auth/v1/");
    hash.update(config.as_str().as_bytes());
    hash.update(seed);
    hash.update(prover_input);
    hash.update(verifier_input);
    hash.finalize().into()
}

/// SHA-256.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
