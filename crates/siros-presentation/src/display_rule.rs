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

/// What A9 judges an offer by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisplayFacts {
    /// Every member credential is registered as presentable without the wallet's UI: its key
    /// signs without user interaction and the wallet's background service answers.
    pub presentable_without_ui: bool,
    /// The request carries `transaction_data`, which its type renders in the wallet (T2).
    pub transaction_data: bool,
    /// Every disclosed claim and every proof statement of the offer has a display row, and no
    /// row is clipped.
    pub rows_whole: bool,
    /// The offer has optional additions to choose.
    pub additions: bool,
}

impl WalletDisplay {
    /// The display an offer of `facts` needs: none of the wallet's when every member is
    /// presentable without the UI, the request carries no `transaction_data`, every row is
    /// shown whole, and nothing is left to choose.
    pub fn of(facts: &DisplayFacts) -> Self {
        if facts.presentable_without_ui
            && !facts.transaction_data
            && facts.rows_whole
            && !facts.additions
        {
            Self::NotNeeded
        } else {
            Self::Needed
        }
    }
}
