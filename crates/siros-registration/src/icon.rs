//! The icons the wallet registers: raster images the host prepared, checked by their headers.
//!
//! The bounds and the formats come from devices and from the owner's wallet:
//! - Credential Manager drops an entry without an icon, and a 4×4 PNG; a 64×64 PNG shows
//!   (`android-credman-sys/ABI.md`, source SD);
//! - Credential Manager shows a PNG the wallet rasterised from an SVG, and no SVG; the owner's
//!   wallet registers PNG and JPEG Data URLs alone, 120 pixels on the long side (ABI.md, source
//!   PW).
//!
//! The upper bound, 256 pixels on the long side, keeps the registration small and holds the
//! owner's 120 pixels with room.

use crate::registration::Icon;

/// The fewest pixels of an icon in either direction.
pub const MIN_ICON_PIXELS: u32 = 64;

/// The most pixels of an icon in either direction.
pub const MAX_ICON_PIXELS: u32 = 256;

/// The PNG signature (PNG, Section 5.2).
const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// The JPEG start-of-image marker and the first byte of the next marker.
const JPEG_SOI: [u8; 3] = [0xff, 0xd8, 0xff];

/// The pixels of an image in each direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dimensions {
    /// The width.
    pub width: u32,
    /// The height.
    pub height: u32,
}

/// A raster icon the host prepared for a picker entry: a PNG or JPEG of
/// [`MIN_ICON_PIXELS`] to [`MAX_ICON_PIXELS`] in each direction. The host rasterises an SVG
/// logo and resizes an image before it passes it; the core reads only the image's header.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RasterIcon(Icon);

/// Why bytes are no raster icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
#[error("{}", self.code())]
pub enum IconFault {
    /// The bytes start with neither the PNG signature nor the JPEG start of image: an SVG
    /// document, for one, which the host rasterises first.
    NotRaster,
    /// The PNG has no IHDR chunk of 13 bytes after its signature.
    PngHeader,
    /// The JPEG ends, or reaches its scan, before a start-of-frame segment.
    JpegFrame,
    /// The image is smaller than [`MIN_ICON_PIXELS`] in a direction: Credential Manager drops it.
    TooSmall(Dimensions),
    /// The image is larger than [`MAX_ICON_PIXELS`] in a direction: the host resizes it first.
    TooLarge(Dimensions),
}

impl IconFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::NotRaster => "icon_not_raster",
            Self::PngHeader => "icon_png_header",
            Self::JpegFrame => "icon_jpeg_frame",
            Self::TooSmall(_) => "icon_too_small",
            Self::TooLarge(_) => "icon_too_large",
        }
    }
}

impl RasterIcon {
    /// The icon `bytes`.
    ///
    /// # Errors
    ///
    /// [`IconFault`]: bytes of no PNG or JPEG, a header that does not read, or dimensions
    /// outside the bounds.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, IconFault> {
        let dimensions = if bytes.starts_with(&PNG_SIGNATURE) {
            png(&bytes)?
        } else if bytes.starts_with(&JPEG_SOI) {
            jpeg(&bytes)?
        } else {
            return Err(IconFault::NotRaster);
        };
        if dimensions.width < MIN_ICON_PIXELS || dimensions.height < MIN_ICON_PIXELS {
            return Err(IconFault::TooSmall(dimensions));
        }
        if dimensions.width > MAX_ICON_PIXELS || dimensions.height > MAX_ICON_PIXELS {
            return Err(IconFault::TooLarge(dimensions));
        }
        Ok(Self(Icon::of_held(bytes)))
    }

    /// The icon, as the registration holds it.
    pub(crate) fn icon(&self) -> &Icon {
        &self.0
    }
}

/// The width and height of the PNG `bytes`, from its IHDR chunk (PNG, Section 11.2.2).
fn png(bytes: &[u8]) -> Result<Dimensions, IconFault> {
    let part = |range: std::ops::Range<usize>| bytes.get(range).ok_or(IconFault::PngHeader);
    if part(8..12)? != [0, 0, 0, 13] || part(12..16)? != b"IHDR" {
        return Err(IconFault::PngHeader);
    }
    Ok(Dimensions {
        width: u32_be(part(16..20)?),
        height: u32_be(part(20..24)?),
    })
}

/// The width and height of the JPEG `bytes`: those of its first start-of-frame segment (ITU-T
/// T.81, Annex B.2.2).
fn jpeg(bytes: &[u8]) -> Result<Dimensions, IconFault> {
    let mut at = 2;
    loop {
        // Fill bytes precede a marker (Annex B.1.1.2).
        while bytes.get(at) == Some(&0xff) && bytes.get(at + 1) == Some(&0xff) {
            at += 1;
        }
        let (Some(0xff), Some(&marker)) = (bytes.get(at), bytes.get(at + 1)) else {
            return Err(IconFault::JpegFrame);
        };
        at += 2;
        // Markers without a segment: TEM and RST0 to RST7.
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = bytes
            .get(at..at + 2)
            .map(|b| usize::from(u16_be(b)))
            .ok_or(IconFault::JpegFrame)?;
        if is_start_of_frame(marker) {
            let part = |from: usize| bytes.get(from..from + 2).ok_or(IconFault::JpegFrame);
            let (height, width) = (u16_be(part(at + 3)?), u16_be(part(at + 5)?));
            return Ok(Dimensions {
                width: u32::from(width),
                height: u32::from(height),
            });
        }
        // Start of scan: the frame header comes before it (Annex B.2.1).
        if marker == 0xda || length < 2 {
            return Err(IconFault::JpegFrame);
        }
        at += length;
    }
}

/// SOF0 to SOF15, except DHT (C4), JPG (C8) and DAC (CC) (Table B.1).
fn is_start_of_frame(marker: u8) -> bool {
    (0xc0..=0xcf).contains(&marker) && !matches!(marker, 0xc4 | 0xc8 | 0xcc)
}

fn u32_be(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0, |value, &b| (value << 8) | u32::from(b))
}

fn u16_be(bytes: &[u8]) -> u16 {
    bytes
        .iter()
        .fold(0, |value, &b| (value << 8) | u16::from(b))
}
