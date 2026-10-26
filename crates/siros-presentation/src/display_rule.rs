//! The wallet's display (A9): whether the user must consent to an offer on the wallet's UI.

/// Whether an offer needs the wallet's display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletDisplay {
    /// The user can consent on the picker's display alone, and the wallet presents without its
    /// UI.
    NotNeeded,
    /// The user consents on the wallet's display.
    Needed,
}

/// Whether the wallet presents a credential from its background service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Presentability {
    /// Every member credential is registered as presentable without the wallet's UI: its key
    /// signs without user interaction and the wallet's background service answers.
    WithoutUi,
    /// A member credential is presentable on the wallet's UI only.
    OnWalletUi,
}

/// Whether the request carries `transaction_data`, which its type renders in the wallet (T2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionData {
    /// No `transaction_data`.
    Absent,
    /// `transaction_data` entries.
    Carried,
}

/// Whether the user still chooses something in an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Choice {
    /// Nothing is left to choose.
    Settled,
    /// The user chooses: optional additions, or a subset of the candidates of a `multiple`
    /// query.
    Open,
}

/// What A9 judges an offer by. Every disclosed claim and every proof statement shows as a row
/// of `DisplayText`, which holds its text whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisplayFacts {
    /// Whether the wallet presents the member credentials from its background service.
    pub presentability: Presentability,
    /// Whether the request carries `transaction_data`.
    pub transaction_data: TransactionData,
    /// Whether the offer has optional additions to choose.
    pub additions: Choice,
    /// Whether a member answers a `multiple` query with more than one candidate, a subset of
    /// which the user chooses.
    pub subsets: Choice,
}

impl WalletDisplay {
    /// The display an offer of `facts` needs: none of the wallet's when every member is
    /// presentable without the UI, the request carries no `transaction_data`, and nothing is
    /// left to choose.
    pub fn of(facts: &DisplayFacts) -> Self {
        let settled = DisplayFacts {
            presentability: Presentability::WithoutUi,
            transaction_data: TransactionData::Absent,
            additions: Choice::Settled,
            subsets: Choice::Settled,
        };
        if *facts == settled {
            Self::NotNeeded
        } else {
            Self::Needed
        }
    }
}
