//! The positions of a registration's lists.

siros_codec::position!(
    /// The position of a credential among the registration's credentials.
    pub CredentialIndex
);

siros_codec::position!(
    /// The position of an icon in the registration's icon table.
    pub IconIndex
);

siros_codec::position!(
    /// The position of a projected definition in the registration's definition table.
    pub DefinitionIndex
);
