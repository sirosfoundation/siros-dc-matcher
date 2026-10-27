//! The header and table directory of a font an SVG document references: an sfnt font,
//! TrueType or OpenType (OpenType 1.9, "Organization of an OpenType Font"), a WOFF font (WOFF
//! 1.0, Sections 3 and 4), or a WOFF2 font (WOFF2, Sections 3 and 4). The directory lists no
//! `SVG ` table: its glyphs are SVG documents outside the static subset (OpenType 1.9, "SVG").

/// The sfnt version of TrueType outlines, and Apple's.
const TRUETYPE: [[u8; 4]; 2] = [[0, 1, 0, 0], *b"true"];

/// The sfnt version of CFF outlines.
const OPENTYPE: [u8; 4] = *b"OTTO";

/// The table records of an sfnt font: 16 bytes each, after a header of 12, the table's
/// offset at 8 and its length at 12.
const SFNT: Directory = Directory {
    header: 12,
    entry: 16,
    offset: 8,
    length: 12,
};

/// The table directory of a WOFF font: 20 bytes an entry, after a header of 44, the compressed
/// table's offset at 4 and its length at 8.
const WOFF: Directory = Directory {
    header: 44,
    entry: 20,
    offset: 4,
    length: 8,
};

/// The WOFF2 header, before the table directory.
const WOFF2_HEADER: usize = 48;

/// The known-tag indices of `glyf` and `loca` (WOFF2, Section 4.1, Table 1).
const GLYF_LOCA: [u8; 2] = [10, 11];

/// The tag of the table of SVG glyph documents.
const SVG_TAG: &[u8; 4] = b"SVG ";

/// The known-tag index of `SVG ` (WOFF2, Section 4.1, Table 1).
const SVG_INDEX: u8 = 36;

/// The flag value that an explicit tag follows (WOFF2, Section 4.1).
const EXPLICIT_TAG: u8 = 63;

/// A font format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FontFormat {
    /// WOFF 1.0, `font/woff`.
    Woff,
    /// WOFF2, `font/woff2`.
    Woff2,
    /// An sfnt font of TrueType outlines, `font/ttf`.
    TrueType,
    /// An sfnt font of CFF outlines, `font/otf`.
    OpenType,
}

impl FontFormat {
    /// The media type (RFC 8081).
    #[must_use]
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Woff => "font/woff",
            Self::Woff2 => "font/woff2",
            Self::TrueType => "font/ttf",
            Self::OpenType => "font/otf",
        }
    }

    /// The format whose signature `bytes` start with.
    pub(super) fn sniff(bytes: &[u8]) -> Option<Self> {
        let signature: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
        match &signature {
            b"wOFF" => Some(Self::Woff),
            b"wOF2" => Some(Self::Woff2),
            _ if TRUETYPE.contains(&signature) => Some(Self::TrueType),
            _ if signature == OPENTYPE => Some(Self::OpenType),
            _ => None,
        }
    }

    /// Checks the header and table directory of the font `bytes`, of this format.
    ///
    /// # Errors
    ///
    /// [`FontFault`]: the first rule the header or directory breaks.
    pub(super) fn check(self, bytes: &[u8]) -> Result<(), FontFault> {
        match self {
            Self::TrueType | Self::OpenType => SFNT.check(bytes, tables(bytes, 4)?),
            Self::Woff => WOFF.check(bytes, wrapped(bytes)?),
            Self::Woff2 => woff2(bytes),
        }
    }
}

/// Why a font's header or table directory does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FontFault {
    /// The font ends inside its header or table directory.
    Truncated,
    /// The WOFF or WOFF2 flavor is neither TrueType nor OpenType outlines.
    Flavor,
    /// The WOFF or WOFF2 header states another length than the font's.
    Length,
    /// The WOFF or WOFF2 header's reserved field is not zero.
    Reserved,
    /// The table directory lists no table.
    NoTables,
    /// A table tag holds a byte outside printable ASCII.
    Tag,
    /// The directory lists the `SVG ` table of SVG glyph documents.
    SvgTable,
    /// A UIntBase128 of the WOFF2 table directory does not read (WOFF2, Section 4.1).
    Base128,
    /// A table, or the WOFF2 compressed data, lies outside the font.
    TableBounds,
}

impl FontFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Truncated => "font_truncated",
            Self::Flavor => "font_flavor",
            Self::Length => "font_length",
            Self::Reserved => "font_reserved",
            Self::NoTables => "font_no_tables",
            Self::Tag => "font_tag",
            Self::SvgTable => "font_svg_table",
            Self::Base128 => "font_base128",
            Self::TableBounds => "font_table_bounds",
        }
    }
}

siros_codec::display_code!(FontFault);

impl std::error::Error for FontFault {}

/// A table directory of entries of a fixed size, each with the offset and length of its table.
struct Directory {
    /// The bytes of the header before the directory.
    header: usize,
    /// The bytes of an entry.
    entry: usize,
    /// The position of the table's offset in an entry.
    offset: usize,
    /// The position of the table's length in an entry.
    length: usize,
}

impl Directory {
    /// Checks the directory of `tables` entries of the font `bytes`: each entry's tag
    /// printable, and its table after the directory and within the font.
    fn check(&self, bytes: &[u8], tables: usize) -> Result<(), FontFault> {
        let end = self.header + tables * self.entry;
        if end > bytes.len() {
            return Err(FontFault::Truncated);
        }
        for entry in (self.header..end).step_by(self.entry) {
            tag(bytes, entry)?;
            let offset = be32(bytes, entry + self.offset)?;
            within(
                bytes,
                end,
                u64::from(offset),
                be32(bytes, entry + self.length)?,
            )?;
        }
        Ok(())
    }
}

/// A WOFF2 font: its header, its table directory read, and its compressed data after the
/// directory and within the font.
fn woff2(bytes: &[u8]) -> Result<(), FontFault> {
    let tables = wrapped(bytes)?;
    let mut at = WOFF2_HEADER;
    for _ in 0..tables {
        let flags = *bytes.get(at).ok_or(FontFault::Truncated)?;
        at += 1;
        let index = flags & 0x3f;
        if index == SVG_INDEX {
            return Err(FontFault::SvgTable);
        }
        let explicit = if index == EXPLICIT_TAG {
            tag(bytes, at)?;
            let explicit = bytes.get(at..at + 4);
            at += 4;
            explicit
        } else {
            None
        };
        let glyf_loca = GLYF_LOCA.contains(&index)
            || explicit.is_some_and(|tag| tag == b"glyf" || tag == b"loca");
        // The transformation version: 3 is the null transform of glyf and loca, 0 of the others.
        let version = flags >> 6;
        at = base128(bytes, at)?;
        if (glyf_loca && version != 3) || (!glyf_loca && version != 0) {
            at = base128(bytes, at)?;
        }
    }
    let start = u64::try_from(at).map_err(|_| FontFault::TableBounds)?;
    within(bytes, at, start, be32(bytes, 20)?)
}

/// The table count of a WOFF or WOFF2 font, its header read: a TrueType or OpenType flavor, its
/// stated length the font's, and its reserved field zero.
fn wrapped(bytes: &[u8]) -> Result<usize, FontFault> {
    let flavor: [u8; 4] = bytes
        .get(4..8)
        .and_then(|flavor| flavor.try_into().ok())
        .ok_or(FontFault::Truncated)?;
    if !TRUETYPE.contains(&flavor) && flavor != OPENTYPE {
        return Err(FontFault::Flavor);
    }
    if usize::try_from(be32(bytes, 8)?).ok() != Some(bytes.len()) {
        return Err(FontFault::Length);
    }
    if be16(bytes, 14)? != 0 {
        return Err(FontFault::Reserved);
    }
    tables(bytes, 12)
}

/// The table count at `at`, at least one.
fn tables(bytes: &[u8], at: usize) -> Result<usize, FontFault> {
    match be16(bytes, at)? {
        0 => Err(FontFault::NoTables),
        count => Ok(usize::from(count)),
    }
}

/// Checks that the tag at `at` is four bytes of printable ASCII other than `SVG `.
fn tag(bytes: &[u8], at: usize) -> Result<(), FontFault> {
    let tag = bytes.get(at..at + 4).ok_or(FontFault::Truncated)?;
    if !tag.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
        Err(FontFault::Tag)
    } else if tag == SVG_TAG {
        Err(FontFault::SvgTable)
    } else {
        Ok(())
    }
}

/// Checks that `length` bytes at `offset` lie at or after `start` and within the font.
fn within(bytes: &[u8], start: usize, offset: u64, length: u32) -> Result<(), FontFault> {
    let end = offset + u64::from(length);
    let (Ok(start), Ok(size)) = (u64::try_from(start), u64::try_from(bytes.len())) else {
        return Err(FontFault::TableBounds);
    };
    if offset >= start && end <= size {
        Ok(())
    } else {
        Err(FontFault::TableBounds)
    }
}

/// The position after the UIntBase128 at `at`: at most 5 bytes, no leading zero byte, and a
/// value within 32 bits (WOFF2, Section 4.1).
fn base128(bytes: &[u8], at: usize) -> Result<usize, FontFault> {
    let mut value: u32 = 0;
    for (count, position) in (at..at + 5).enumerate() {
        let byte = *bytes.get(position).ok_or(FontFault::Truncated)?;
        if (count == 0 && byte == 0x80) || value & 0xfe00_0000 != 0 {
            return Err(FontFault::Base128);
        }
        value = (value << 7) | u32::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok(position + 1);
        }
    }
    Err(FontFault::Base128)
}

fn be32(bytes: &[u8], at: usize) -> Result<u32, FontFault> {
    let field: [u8; 4] = bytes
        .get(at..at + 4)
        .and_then(|field| field.try_into().ok())
        .ok_or(FontFault::Truncated)?;
    Ok(u32::from_be_bytes(field))
}

fn be16(bytes: &[u8], at: usize) -> Result<u16, FontFault> {
    let field: [u8; 2] = bytes
        .get(at..at + 2)
        .and_then(|field| field.try_into().ok())
        .ok_or(FontFault::Truncated)?;
    Ok(u16::from_be_bytes(field))
}
