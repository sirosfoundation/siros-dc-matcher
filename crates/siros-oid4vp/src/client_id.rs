//! Client Identifiers and their prefixes (OpenID4VP 1.0, Section 5.9).

use crate::intake::IntakeError;

/// A Client Identifier Prefix this wallet supports (OpenID4VP 1.0, Section 5.9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientIdPrefix {
    /// `redirect_uri`: the value is the Response URI. Unsigned requests only.
    RedirectUri,
    /// `x509_san_dns`: the value is a dNSName SAN of the leaf certificate in `x5c`.
    X509SanDns,
    /// `x509_hash`: the value is the base64url SHA-256 of the leaf certificate in `x5c`.
    X509Hash,
    /// `decentralized_identifier`: the value is a DID; `kid` names its key.
    DecentralizedIdentifier,
    /// `verifier_attestation`: the value is the `sub` of the Verifier Attestation JWT in `jwt`.
    VerifierAttestation,
    /// `openid_federation`: the value is an OpenID Federation Entity Identifier.
    OpenidFederation,
}

impl ClientIdPrefix {
    /// Every prefix, in the order `client_id_prefixes_supported` lists them.
    pub(crate) const ALL: [Self; 6] = [
        Self::RedirectUri,
        Self::X509SanDns,
        Self::X509Hash,
        Self::DecentralizedIdentifier,
        Self::VerifierAttestation,
        Self::OpenidFederation,
    ];

    /// The prefix as written before the first `:`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RedirectUri => "redirect_uri",
            Self::X509SanDns => "x509_san_dns",
            Self::X509Hash => "x509_hash",
            Self::DecentralizedIdentifier => "decentralized_identifier",
            Self::VerifierAttestation => "verifier_attestation",
            Self::OpenidFederation => "openid_federation",
        }
    }

    fn named(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == text)
    }
}

/// A `client_id` with a supported prefix and a non-empty value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientId {
    prefix: ClientIdPrefix,
    full: String,
}

impl ClientId {
    /// Parses a `client_id`: the prefix is the text before the first `:` (Section 5.9.1).
    ///
    /// # Errors
    ///
    /// [`IntakeError::ClientIdPrefixUnsupported`] for a `client_id` without `:` (a
    /// pre-registered client), with another prefix (`origin` included, Section 5.9.3), with an
    /// empty value, or a `decentralized_identifier` value that is not a DID.
    pub fn parse(full: &str) -> Result<Self, IntakeError> {
        let (prefix, value) = full
            .split_once(':')
            .ok_or(IntakeError::ClientIdPrefixUnsupported)?;
        let prefix = ClientIdPrefix::named(prefix).ok_or(IntakeError::ClientIdPrefixUnsupported)?;
        let well_formed = match prefix {
            ClientIdPrefix::DecentralizedIdentifier => value.starts_with("did:"),
            _ => !value.is_empty(),
        };
        if !well_formed {
            return Err(IntakeError::ClientIdPrefixUnsupported);
        }
        Ok(Self {
            prefix,
            full: full.to_owned(),
        })
    }

    /// The prefix.
    #[must_use]
    pub fn prefix(&self) -> ClientIdPrefix {
        self.prefix
    }

    /// The original Client Identifier: the part after the prefix and its `:`.
    #[must_use]
    pub fn value(&self) -> &str {
        self.full
            .get(self.prefix.as_str().len() + 1..)
            .unwrap_or_default()
    }

    /// The whole `client_id`, prefix included, as the audience and the redirect `Handover`
    /// use it (Section 14.8).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.full
    }
}
