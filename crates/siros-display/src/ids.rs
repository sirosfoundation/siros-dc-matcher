//! The identifiers that key display metadata.

siros_codec::text_value!(
    /// A Credential Issuer Identifier: the `credential_issuer` of OpenID4VCI issuer metadata
    /// (OpenID4VCI 1.0, Section 12.2.4).
    IssuerIdentifier
);

siros_codec::text_value!(
    /// A credential configuration identifier: a key of `credential_configurations_supported`
    /// (OpenID4VCI 1.0, Section 12.2.4).
    ConfigurationId
);
