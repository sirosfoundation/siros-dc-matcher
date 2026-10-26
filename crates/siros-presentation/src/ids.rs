//! The identifiers and positions the plan, its view and the selection carry.

/// Declares a position among the items of one list of the plan: constructed by the crate as it
/// enumerates the list, read as a number.
macro_rules! position {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value` in its list.
            pub(crate) fn at(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            pub fn value(self) -> usize {
                self.0
            }
        }
    };
}

#[cfg(feature = "wallet")]
pub(crate) use position;

/// Declares a position the host names in a selection: any number, which the plan judges.
macro_rules! chosen {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(usize);

        impl $name {
            /// The position `value`, as the host names it.
            pub fn new(value: usize) -> Self {
                Self(value)
            }

            /// The position, from 0.
            pub fn value(self) -> usize {
                self.0
            }
        }
    };
}

position!(
    /// The position of a Credential Query in the DCQL query's `credentials`.
    QueryIndex
);

position!(
    /// The position of a candidate among the candidates of its Credential Query.
    CandidateIndex
);

position!(
    /// The position of a credential set in the DCQL query's `credential_sets`.
    SetIndex
);

position!(
    /// The position of an option among the options of a `zkp_req` query.
    OptionIndex
);

chosen!(
    /// The position of an offer in the consent view.
    OfferIndex
);

chosen!(
    /// The position of an addition among the additions of an offer in the consent view.
    AdditionIndex
);

chosen!(
    /// The position of a credential among the credentials of a member in the consent view.
    Position
);
