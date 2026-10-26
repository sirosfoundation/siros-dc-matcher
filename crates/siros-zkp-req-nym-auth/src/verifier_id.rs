//! The Verifier's identity, and `verifier_input` and the `sha-256` pseudonym it selects
//! (nym_auth catalogue, `pseudonym`: "Verifier identity" and "Configurations").

use std::fmt;

use sha2::{Digest, Sha256};

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
    /// The form is `x509_san_dns` and the Client Identifier has another prefix.
    ClientIdPrefix,
    /// The form is `x509_san_dns` and the DNS name is empty or not ASCII (an A-label form).
    DnsName,
    /// The form is `x509_san_dns` and the registration certificate names an intermediary.
    Intermediary,
}

impl VerifierIdRule {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::SemanticIdMissing => "semantic_id_missing",
            Self::ClientIdPrefix => "client_id_prefix",
            Self::DnsName => "dns_name",
            Self::Intermediary => "intermediary",
        }
    }
}

impl fmt::Display for VerifierIdRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for VerifierIdRule {}

/// The prefix of the `x509_san_dns` form and of its Client Identifier Prefix.
const X509_SAN_DNS: &str = "x509_san_dns:";

impl VerifierId {
    /// The `semantic` form: `"semantic_id:"` and the end Relying Party's semantic identifier,
    /// from the registration certificate when present, else from the access certificate.
    ///
    /// # Errors
    ///
    /// [`VerifierIdRule::SemanticIdMissing`] for an empty identifier.
    pub fn semantic(semantic_identifier: &str) -> Result<Self, VerifierIdRule> {
        if semantic_identifier.is_empty() {
            return Err(VerifierIdRule::SemanticIdMissing);
        }
        Ok(Self(format!("semantic_id:{semantic_identifier}")))
    }

    /// The `x509_san_dns` form: the Client Identifier itself.
    ///
    /// # Errors
    ///
    /// [`VerifierIdRule`]: another prefix, a DNS name that is empty or not ASCII, or an
    /// intermediary.
    pub fn x509_san_dns(
        client_id: &str,
        registration_names_intermediary: bool,
    ) -> Result<Self, VerifierIdRule> {
        let name = client_id
            .strip_prefix(X509_SAN_DNS)
            .ok_or(VerifierIdRule::ClientIdPrefix)?;
        if name.is_empty() || !name.is_ascii() {
            return Err(VerifierIdRule::DnsName);
        }
        if registration_names_intermediary {
            return Err(VerifierIdRule::Intermediary);
        }
        Ok(Self(client_id.to_owned()))
    }

    /// The identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The form of `verifier_id` the Verifier's trust framework fixes, with what the Wallet takes
/// it from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VerifierIdForm {
    /// `semantic`, with the end Relying Party's semantic identifier from the registration
    /// certificate when present, else from the access certificate.
    Semantic(String),
    /// `x509_san_dns`, with whether the registration certificate names an intermediary.
    X509SanDns {
        /// Whether the registration certificate names an intermediary.
        registration_names_intermediary: bool,
    },
}

impl VerifierIdForm {
    /// The `verifier_id` of this form for the Client Identifier `client_id`, prefix included.
    ///
    /// # Errors
    ///
    /// [`VerifierIdRule`]: the rule of the form the identifier breaks.
    pub fn verifier_id(&self, client_id: &str) -> Result<VerifierId, VerifierIdRule> {
        match self {
            Self::Semantic(identifier) => VerifierId::semantic(identifier),
            Self::X509SanDns {
                registration_names_intermediary,
            } => VerifierId::x509_san_dns(client_id, *registration_names_intermediary),
        }
    }
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
