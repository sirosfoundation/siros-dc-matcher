//! The positions of a registration's parts.

siros_codec::position!(
    /// The position of a credential in the wallet's order, which its record holds.
    pub CredentialIndex
);

siros_codec::position!(
    /// The position of an entry in the registration's index.
    pub KeyIndex
);

siros_codec::position!(
    /// The position of a record among the records of its type.
    pub RecordIndex
);
