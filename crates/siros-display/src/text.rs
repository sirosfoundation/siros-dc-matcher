//! Display text: the only text the core puts on a screen.

use std::cmp::Ordering;
use std::fmt;

mod unsafe_ranges;

use unsafe_ranges::UNSAFE;

/// The most characters of a label, a name, a title or a hint. EC TS12 v1.0.1, Section 3.3.3
/// allows 250.
pub const LABEL_MAX: usize = 500;

/// The most characters of a value. The TS12 mandate text holds at most 1000.
pub const VALUE_MAX: usize = 2_000;

/// A card's title or issuer line: a label with a character other than white space.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CardText(DisplayText);

impl CardText {
    /// The line `text`.
    ///
    /// # Errors
    ///
    /// [`TextError::Empty`] for white space alone; the rule of [`DisplayText::label`] it breaks.
    pub fn new(text: &str) -> Result<Self, TextError> {
        if text.chars().all(char::is_whitespace) {
            return Err(TextError::Empty);
        }
        DisplayText::label(text).map(Self)
    }

    /// The line `text`, when it has a character other than white space.
    pub fn of(text: &DisplayText) -> Option<Self> {
        (!text.as_str().chars().all(char::is_whitespace)).then(|| Self(text.clone()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Text that is safe to show.
///
/// It holds no character of the Unicode general categories Cc (control), Cf (format: the bidi
/// embeddings, overrides and isolates, the bidi marks and the zero-width characters), Zl and Zp
/// (line and paragraph separators), Co (private use) and Cn (unassigned, as of Unicode 16.0).
/// Spaces are safe. Unsafe or over-long text is refused whole: the user sees exactly the text
/// that the other party acts on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisplayText(String);

impl DisplayText {
    /// A label, a name, a title or a hint: at most [`LABEL_MAX`] characters.
    ///
    /// # Errors
    ///
    /// [`TextError`]: the rule `text` breaks.
    pub fn label(text: &str) -> Result<Self, TextError> {
        Self::new(text, LABEL_MAX)
    }

    /// A value: at most [`VALUE_MAX`] characters.
    ///
    /// # Errors
    ///
    /// [`TextError`]: the rule `text` breaks.
    pub fn value(text: &str) -> Result<Self, TextError> {
        Self::new(text, VALUE_MAX)
    }

    fn new(text: &str, max: usize) -> Result<Self, TextError> {
        if text.chars().any(unsafe_to_show) {
            return Err(TextError::Unsafe);
        }
        if text.chars().count() > max {
            return Err(TextError::TooLong);
        }
        Ok(Self(text.to_owned()))
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DisplayText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `c` is of the categories Cc, Cf, Zl, Zp, Co or Cn.
fn unsafe_to_show(c: char) -> bool {
    let code = u32::from(c);
    UNSAFE
        .binary_search_by(|&(first, last)| {
            if last < code {
                Ordering::Less
            } else if first > code {
                Ordering::Greater
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

/// Why text is refused for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum TextError {
    /// The text holds a control, format, separator, private-use or unassigned character.
    Unsafe,
    /// The text has more characters than its kind allows.
    TooLong,
    /// The text of a card's title or issuer line is white space alone.
    Empty,
}

impl TextError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsafe => "text_unsafe",
            Self::TooLong => "text_too_long",
            Self::Empty => "text_empty",
        }
    }
}
