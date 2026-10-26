//! D2: the locale choice, as one table.

use siros_display::{choose, Locale, Localized};

struct Entry(Option<Locale>);

impl Localized for Entry {
    fn locale(&self) -> Option<&Locale> {
        self.0.as_ref()
    }
}

fn locales(tags: &[&str]) -> Vec<Locale> {
    tags.iter()
        .map(|tag| Locale::parse(tag).unwrap_or_else(|e| panic!("{tag}: {e}")))
        .collect()
}

/// A case, the preferences, the entry locales, and the index of the entry chosen.
type Row<'a> = (&'a str, &'a [&'a str], &'a [Option<&'a str>], Option<usize>);

#[test]
fn the_choice_takes_the_exact_tag_then_the_primary_language_then_the_first_entry() {
    let table: &[Row<'_>] = &[
        (
            "exact tag before primary language",
            &["de-DE"],
            &[Some("en-US"), Some("de"), Some("de-DE")],
            Some(2),
        ),
        (
            "tags compare without case",
            &["EN-us"],
            &[Some("de"), Some("en-US")],
            Some(1),
        ),
        (
            "primary language",
            &["de-AT"],
            &[Some("en-US"), Some("de-DE")],
            Some(1),
        ),
        (
            "primary language of a tag with script and region",
            &["zh-Hant-TW"],
            &[Some("en"), Some("zh-Hans-CN")],
            Some(1),
        ),
        (
            "a preference before a match on a later one",
            &["fr-CA", "en-US"],
            &[Some("en-US"), Some("fr-FR")],
            Some(1),
        ),
        (
            "a later preference before the first entry",
            &["ja-JP", "de"],
            &[Some("en-US"), Some("de-DE")],
            Some(1),
        ),
        (
            "the first entry without any match",
            &["ja-JP"],
            &[Some("en-US"), Some("de-DE")],
            Some(0),
        ),
        (
            "an entry without locale matches no preference",
            &["en"],
            &[None, Some("en")],
            Some(1),
        ),
        (
            "an entry without locale may be the first entry",
            &["ja"],
            &[None, Some("en")],
            Some(0),
        ),
        ("no preference", &[], &[Some("de"), Some("en")], Some(0)),
        ("no entry", &["en"], &[], None),
        (
            "a grandfathered tag",
            &["i-klingon"],
            &[Some("en"), Some("i-klingon")],
            Some(1),
        ),
        (
            "a private-use tag",
            &["x-siros"],
            &[Some("en"), Some("x-siros")],
            Some(1),
        ),
    ];
    for (case, preferences, entries, expected) in table {
        let preferences = locales(preferences);
        let entries: Vec<Entry> = entries
            .iter()
            .map(|tag| Entry(tag.map(|t| locales(&[t]).remove(0))))
            .collect();
        let chosen = choose(&preferences, &entries)
            .and_then(|entry| entries.iter().position(|e| std::ptr::eq(e, entry)));
        assert_eq!(chosen, *expected, "{case}");
    }
}
