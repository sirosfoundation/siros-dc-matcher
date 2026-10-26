//! Why display refuses an input. Each error has a stable code.

use std::fmt;

/// Why display refuses an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisplayError {
    /// A `zkp_req` option names a `_req` index its query lacks.
    OptionItemUnknown,
}

impl DisplayError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::OptionItemUnknown => "option_item_unknown",
        }
    }
}

impl fmt::Display for DisplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for DisplayError {}
