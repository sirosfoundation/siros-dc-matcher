//! The character and length rules of PaSO Proof Metadata, Section 3.3: labels, by role, and the
//! string values of a payload.

use std::fmt;
use std::marker::PhantomData;

use unicode_segmentation::UnicodeSegmentation;

/// What a label or a payload string breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TextFault {
    /// A label holds this C0 or C1 control character.
    Control(char),
    /// The text holds this directional embedding or override character, U+202A to U+202E.
    DirectionalOverride(char),
    /// A directional isolate, U+2066 to U+2068, has no U+2069 that terminates it.
    IsolateUnterminated,
    /// A U+2069 terminates no directional isolate.
    IsolateUnopened,
    /// The label has this many extended grapheme clusters, more than its role allows.
    TooLong(usize),
}

impl TextFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Control(_) => "label_control_character",
            Self::DirectionalOverride(_) => "text_directional_override",
            Self::IsolateUnterminated => "text_isolate_unterminated",
            Self::IsolateUnopened => "text_isolate_unopened",
            Self::TooLong(_) => "label_too_long",
        }
    }
}

siros_codec::display_code!(TextFault);

impl std::error::Error for TextFault {}

/// The role of a label, which sets its most extended grapheme clusters (Section 3.3).
pub trait LabelRole {
    /// The most extended grapheme clusters.
    const MAX: usize;
}

/// The `name` of a claim `display` entry: 60.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimName {}

/// `transaction_title`: 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransactionTitle {}

/// `affirmative_action_label` and `denial_action_label`: 40.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionLabel {}

/// `security_hint`: 160, plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityHint {}

/// A UI element another specification or a rulebook defines without its own maximum: 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OtherUiElement {}

impl LabelRole for ClaimName {
    const MAX: usize = 60;
}

impl LabelRole for TransactionTitle {
    const MAX: usize = 100;
}

impl LabelRole for ActionLabel {
    const MAX: usize = 40;
}

impl LabelRole for SecurityHint {
    const MAX: usize = 160;
}

impl LabelRole for OtherUiElement {
    const MAX: usize = 100;
}

/// Whether a label's text is final or a template whose interpolated result the length rule
/// governs (Section 3.3; PaSO View, Section 3, `template:`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelLength {
    /// The text is shown as it is: its length is checked now.
    Final,
    /// The text holds placeholders: its length is checked after interpolation.
    Template,
}

/// A label of role `R`: no C0 or C1 control, no directional embedding or override, every
/// isolate terminated, and, when final, at most `R::MAX` extended grapheme clusters.
pub struct LabelText<R> {
    text: String,
    role: PhantomData<R>,
}

impl<R: LabelRole> LabelText<R> {
    /// The label `text`, whose length rule `length` says when to check.
    ///
    /// # Errors
    ///
    /// [`TextFault`]: the first rule `text` breaks.
    pub fn parse(text: &str, length: LabelLength) -> Result<Self, TextFault> {
        if let Some(control) = text.chars().find(|c| is_c0_or_c1(*c)) {
            return Err(TextFault::Control(control));
        }
        bidi(text)?;
        if length == LabelLength::Final {
            fits::<R>(text)?;
        }
        Ok(Self {
            text: text.to_owned(),
            role: PhantomData,
        })
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl<R> Clone for LabelText<R> {
    fn clone(&self) -> Self {
        Self {
            text: self.text.clone(),
            role: PhantomData,
        }
    }
}

impl<R> PartialEq for LabelText<R> {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl<R> Eq for LabelText<R> {}

impl<R> fmt::Debug for LabelText<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LabelText").field(&self.text).finish()
    }
}

/// Checks that `text`, a label of role `R`, has at most `R::MAX` extended grapheme clusters
/// (UAX #29).
///
/// # Errors
///
/// [`TextFault::TooLong`].
pub(crate) fn fits<R: LabelRole>(text: &str) -> Result<(), TextFault> {
    let length = text.graphemes(true).count();
    if length > R::MAX {
        Err(TextFault::TooLong(length))
    } else {
        Ok(())
    }
}

/// Checks the directional characters of `text`, a label or a payload string value: none of
/// U+202A to U+202E, and each isolate U+2066 to U+2068 terminated by U+2069 (Section 3.3).
///
/// # Errors
///
/// [`TextFault`]: the first directional rule `text` breaks.
pub(crate) fn bidi(text: &str) -> Result<(), TextFault> {
    let mut open = 0usize;
    for c in text.chars() {
        match c {
            '\u{202a}'..='\u{202e}' => return Err(TextFault::DirectionalOverride(c)),
            '\u{2066}'..='\u{2068}' => open += 1,
            '\u{2069}' => open = open.checked_sub(1).ok_or(TextFault::IsolateUnopened)?,
            _ => {}
        }
    }
    if open == 0 {
        Ok(())
    } else {
        Err(TextFault::IsolateUnterminated)
    }
}

/// Whether `c` is a C0 (U+0000 to U+001F) or C1 (U+0080 to U+009F) control character.
fn is_c0_or_c1(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{80}'..='\u{9f}')
}
