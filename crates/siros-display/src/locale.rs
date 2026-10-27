//! The locale function (D2): RFC 4647 Lookup with the wallet's language, then the entry without
//! a locale (PaSO View, Section 4).

pub use siros_codec::locale::{Locale, LocaleError};

/// An entry of display metadata for one locale, or for an unstated one.
pub trait Localized {
    /// The entry's locale. `None` when the entry states none.
    fn locale(&self) -> Option<&Locale>;
}

impl<T: Localized + ?Sized> Localized for &T {
    fn locale(&self) -> Option<&Locale> {
        (**self).locale()
    }
}

/// The entry of `entries` to show in the wallet's `language` (D2; PaSO View, Section 4): the
/// entry RFC 4647 Lookup (Section 3.4) finds with `language` as the language range and the
/// entries' locales as the available tags, else the first entry without a locale. `None` when
/// neither exists.
///
/// Lookup tries the range whole, then truncated one subtag at a time from the end. Tags compare
/// without regard to ASCII case.
pub fn lookup<'a, T: Localized>(language: &Locale, entries: &'a [T]) -> Option<&'a T> {
    lookup_ranges(language)
        .find_map(|range| {
            entries.iter().find(|entry| {
                entry
                    .locale()
                    .is_some_and(|tag| tag.as_str().eq_ignore_ascii_case(range))
            })
        })
        .or_else(|| entries.iter().find(|entry| entry.locale().is_none()))
}

/// The language ranges RFC 4647 Lookup tries for `language`, longest first (Section 3.4).
fn lookup_ranges(language: &Locale) -> impl Iterator<Item = &str> {
    let mut next = Some(language.as_str());
    std::iter::from_fn(move || {
        let range = next?;
        next = truncated(range);
        Some(range)
    })
}

/// `range` without its last subtag; `None` for a range of one subtag. RFC 4647 also drops a
/// singleton the cut leaves at the end; no well-formed tag ends in one, so that range matches
/// nothing either way.
fn truncated(range: &str) -> Option<&str> {
    range.rsplit_once('-').map(|(rest, _)| rest)
}
