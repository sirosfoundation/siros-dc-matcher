//! A linear scan of an XML document's markup before the parser reads it (XML 1.0, Sections 2.5
//! to 2.8 and 3.1): the nesting of its elements, at most [`MAX_DEPTH`] levels, and its DOCTYPE,
//! whose external identifier, when it has one, is a W3C SVG 1.0 or 1.1 DTD's.
//! The scan delimits comments, CDATA sections, processing instructions, the DOCTYPE and quoted
//! attribute values as XML does. Where the markup breaks XML, the scan ends: the parser refuses
//! the document there, with no element open beyond those the scan counted.

use super::SvgFault;

/// The most levels of nested elements in an SVG document. The parser recurses once per level;
/// 128 levels fit a 2 MiB thread stack in a debug build.
pub const MAX_DEPTH: usize = 128;

/// The public and system identifiers of the W3C SVG 1.0 and 1.1 DTDs.
const IDENTIFIERS: [(&str, &str); 5] = [
    (
        "-//W3C//DTD SVG 1.0//EN",
        "http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd",
    ),
    (
        "-//W3C//DTD SVG 20010904//EN",
        "http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd",
    ),
    (
        "-//W3C//DTD SVG 1.1//EN",
        "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd",
    ),
    (
        "-//W3C//DTD SVG 1.1 Basic//EN",
        "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11-basic.dtd",
    ),
    (
        "-//W3C//DTD SVG 1.1 Tiny//EN",
        "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11-tiny.dtd",
    ),
];

/// The markup that opens and closes around the content it skips.
const SKIPPED: [(&[u8], &[u8]); 3] = [(b"<!--", b"-->"), (b"<![CDATA[", b"]]>"), (b"<?", b"?>")];

/// The DOCTYPE of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Doctype {
    /// The document has none.
    Absent,
    /// A name and, when any, the external identifier of a W3C SVG 1.0 or 1.1 DTD: the parser
    /// reads it and loads nothing.
    External,
    /// An internal subset, whose entities the parser would expand.
    Internal,
}

impl Doctype {
    /// Whether the parser may read the DOCTYPE.
    pub(super) fn readable(self) -> bool {
        self == Self::External
    }
}

/// The markup at a `<`, each with the position after it.
enum Markup {
    /// A comment, a CDATA section or a processing instruction.
    Skipped(usize),
    /// A DOCTYPE without an internal subset, and whether it names no external identifier but
    /// a W3C SVG DTD's.
    Doctype(usize, bool),
    /// A DOCTYPE with an internal subset.
    Subset,
    /// An end tag.
    Close(usize),
    /// A start tag, and whether it is an empty-element tag.
    Open(usize, bool),
    /// Markup that breaks XML.
    Broken,
}

/// The DOCTYPE of `text`, its elements nested at most [`MAX_DEPTH`] levels.
///
/// # Errors
///
/// [`SvgFault::Nesting`] for an element nested deeper, and [`SvgFault::Doctype`] for an external
/// identifier of another DTD.
pub(super) fn scan(text: &str) -> Result<Doctype, SvgFault> {
    let bytes = text.as_bytes();
    let mut doctype = Doctype::Absent;
    let mut depth = 0_usize;
    let mut rooted = false;
    let mut at = 0;
    while let Some(start) = find(bytes, at, b"<") {
        at = match markup(bytes, start, rooted) {
            Markup::Skipped(end) => end,
            Markup::Doctype(end, true) => {
                doctype = Doctype::External;
                end
            }
            Markup::Doctype(end, false) => {
                let declaration = text.get(start..end).unwrap_or_default();
                return Err(SvgFault::Doctype(declaration.to_owned()));
            }
            Markup::Subset => return Ok(Doctype::Internal),
            Markup::Broken => break,
            Markup::Close(end) => {
                depth = depth.saturating_sub(1);
                end
            }
            Markup::Open(end, empty) => {
                rooted = true;
                let level = depth + 1;
                if level > MAX_DEPTH {
                    return Err(SvgFault::Nesting);
                }
                if !empty {
                    depth = level;
                }
                end
            }
        };
    }
    Ok(doctype)
}

/// The markup at `start`, a DOCTYPE only before the root element.
fn markup(bytes: &[u8], start: usize, rooted: bool) -> Markup {
    let rest = bytes.get(start..).unwrap_or_default();
    if let Some((open, close)) = SKIPPED.iter().find(|(open, _)| rest.starts_with(open)) {
        return find(bytes, start + open.len(), close)
            .map_or(Markup::Broken, |end| Markup::Skipped(end + close.len()));
    }
    if rest.starts_with(b"<!DOCTYPE") && !rooted {
        declared(bytes, start)
    } else if rest.starts_with(b"<!") {
        Markup::Broken
    } else if rest.starts_with(b"</") {
        find(bytes, start + 2, b">").map_or(Markup::Broken, |end| Markup::Close(end + 1))
    } else {
        tag_end(bytes, start).map_or(Markup::Broken, |(end, empty)| Markup::Open(end, empty))
    }
}

/// The DOCTYPE at `start`: its quoted literals read, an internal subset at its first `[`
/// (Section 2.8, `doctypedecl`).
fn declared(bytes: &[u8], start: usize) -> Markup {
    let mut at = start;
    let mut literals: Vec<&[u8]> = Vec::new();
    while let Some(&byte) = bytes.get(at) {
        at = match byte {
            b'"' | b'\'' => match find(bytes, at + 1, &[byte]) {
                Some(quote) => {
                    literals.push(bytes.get(at + 1..quote).unwrap_or_default());
                    quote + 1
                }
                None => return Markup::Broken,
            },
            b'[' => return Markup::Subset,
            b'>' => return Markup::Doctype(at + 1, svg_dtd(&literals)),
            _ => at + 1,
        };
    }
    Markup::Broken
}

/// Whether the quoted `literals` of a DOCTYPE name no external identifier, a W3C SVG DTD's
/// system identifier, or the public and system identifiers of one.
fn svg_dtd(literals: &[&[u8]]) -> bool {
    let named = |public: Option<&[u8]>, system: &[u8]| {
        IDENTIFIERS.iter().any(|(known_public, known_system)| {
            public.is_none_or(|public| public == known_public.as_bytes())
                && system == known_system.as_bytes()
        })
    };
    match literals {
        [] => true,
        [system] => named(None, system),
        [public, system] => named(Some(public), system),
        _ => false,
    }
}

/// The position after the start tag at `start`, and whether it is an empty-element tag
/// (Section 3.1). An attribute value runs to its closing quote and holds no `<`; `None` for a
/// tag that breaks that or has no end.
fn tag_end(bytes: &[u8], start: usize) -> Option<(usize, bool)> {
    let mut at = start + 1;
    let mut slash = false;
    loop {
        let byte = *bytes.get(at)?;
        match byte {
            b'"' | b'\'' => {
                let quote = find(bytes, at + 1, &[byte])?;
                if bytes.get(at + 1..quote)?.contains(&b'<') {
                    return None;
                }
                at = quote + 1;
                slash = false;
            }
            b'<' => return None,
            b'>' => return Some((at + 1, slash)),
            _ => {
                slash = byte == b'/';
                at += 1;
            }
        }
    }
}

/// The position of the first `needle` at or after `from`.
fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    bytes
        .get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}
