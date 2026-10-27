//! Display text: the only text the core puts on a screen.

use std::fmt;

use unicode_general_category::{get_general_category, GeneralCategory};

/// The most characters of a label, a name, a title or a hint. EC TS12 v1.0.1, Section 3.3.3
/// allows 250.
pub const LABEL_MAX: usize = 500;

/// The most characters of a value. The TS12 mandate text holds at most 1000.
pub const VALUE_MAX: usize = 2_000;

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

/// A `char` excludes the surrogates (Cs), so the categories Cc, Cf, Zl, Zp, Co and Cn remain.
fn unsafe_to_show(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::Control
            | GeneralCategory::Format
            | GeneralCategory::LineSeparator
            | GeneralCategory::ParagraphSeparator
            | GeneralCategory::PrivateUse
            | GeneralCategory::Unassigned
    )
}

/// Why text is refused for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextError {
    /// The text holds a control, format, separator, private-use or unassigned character.
    Unsafe,
    /// The text has more characters than its kind allows.
    TooLong,
}

impl TextError {
    /// A stable identifier.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unsafe => "text_unsafe",
            Self::TooLong => "text_too_long",
        }
    }
}

siros_codec::display_code!(TextError);

impl std::error::Error for TextError {}
