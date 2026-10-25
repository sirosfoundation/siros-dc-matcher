use c8str::{C8String, NonZeroChar};
use core::fmt;

/// Appends to a [`C8String`] that cannot fail: a NUL in the text becomes a
/// space.
pub trait C8StringExt {
    /// `text` as a host string.
    fn from_str_lossy(text: &str) -> Self;

    /// Appends `text`.
    fn push_str_lossy(&mut self, text: &str);

    /// A [`fmt::Write`] that appends to this string.
    fn writer(&mut self) -> C8Writer<'_>;
}

const SPACE: Option<NonZeroChar> = NonZeroChar::new(' ');

impl C8StringExt for C8String {
    fn from_str_lossy(text: &str) -> Self {
        let mut string = C8String::new();
        string.push_str_lossy(text);
        string
    }

    fn push_str_lossy(&mut self, text: &str) {
        if self.push_str(text).is_ok() {
            return;
        }
        // `push_str` refuses only an interior NUL, and appends nothing then.
        for ch in text.chars() {
            if let Some(ch) = NonZeroChar::new(ch).or(SPACE) {
                self.push(ch);
            }
        }
    }

    fn writer(&mut self) -> C8Writer<'_> {
        C8Writer(self)
    }
}

/// A [`fmt::Write`] over a [`C8String`], from [`C8StringExt::writer`]. It
/// appends with [`C8StringExt::push_str_lossy`] and never fails.
#[derive(Debug)]
pub struct C8Writer<'a>(&'a mut C8String);

impl fmt::Write for C8Writer<'_> {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.0.push_str_lossy(text);
        Ok(())
    }
}
