//! The positions that refusals and errors name.

/// Declares a position among the items of one list: a number, from 0.
macro_rules! position {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value`.
            #[must_use]
            pub fn new(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            #[must_use]
            pub fn value(self) -> usize {
                self.0
            }
        }
    };
}

position!(
    /// The position of a certificate in an issuer chain: 0 for the chain's first certificate.
    ChainIndex
);

position!(
    /// The position of an entry in a trust store record.
    EntryIndex
);

position!(
    /// The position of a certificate among the `certificates` of a trust store entry.
    CertificateIndex
);
