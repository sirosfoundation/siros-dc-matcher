//! A linear scan of an XML document's markup before the parser reads it (XML 1.0, Sections 2.5
//! to 2.8 and 3.1): the nesting of its elements, at most [`MAX_DEPTH`] levels, and its DOCTYPE.
//! The scan delimits comments, CDATA sections, processing instructions, the DOCTYPE and quoted
//! attribute values as XML does. Where the markup breaks XML, the scan ends: the parser refuses
//! the document there, with no element open beyond those the scan counted.

use super::SvgFault;

/// The most levels of nested elements in an SVG document. The parser recurses once per level;
/// 128 levels fit a 2 MiB thread stack in a debug build.
pub const MAX_DEPTH: usize = 128;

/// The markup that opens and closes around the content it skips.
const SKIPPED: [(&[u8], &[u8]); 3] = [(b"<!--", b"-->"), (b"<![CDATA[", b"]]>"), (b"<?", b"?>")];

/// The DOCTYPE of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Doctype {
    /// The document has none.
    Absent,
    /// A name and an external identifier: the parser reads it and loads nothing.
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
    /// A DOCTYPE without an internal subset.
    Doctype(usize),
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
/// [`SvgFault::Nesting`] for an element nested deeper.
pub(super) fn scan(text: &str) -> Result<Doctype, SvgFault> {
    let bytes = text.as_bytes();
    let mut doctype = Doctype::Absent;
    let mut depth = 0_usize;
    let mut rooted = false;
    let mut at = 0;
    while let Some(start) = find(bytes, at, b"<") {
        at = match markup(bytes, start, rooted) {
            Markup::Skipped(end) => end,
            Markup::Doctype(end) => {
                doctype = Doctype::External;
                end
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

/// The DOCTYPE at `start`: its quoted literals skipped, an internal subset at its first `[`
/// (Section 2.8, `doctypedecl`).
fn declared(bytes: &[u8], start: usize) -> Markup {
    let mut at = start;
    while let Some(&byte) = bytes.get(at) {
        at = match byte {
            b'"' | b'\'' => match find(bytes, at + 1, &[byte]) {
                Some(quote) => quote + 1,
                None => return Markup::Broken,
            },
            b'[' => return Markup::Subset,
            b'>' => return Markup::Doctype(at + 1),
            _ => at + 1,
        };
    }
    Markup::Broken
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
