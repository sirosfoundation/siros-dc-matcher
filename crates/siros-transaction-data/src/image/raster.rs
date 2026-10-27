//! The pixel dimensions of a PNG image, from its IHDR chunk (PNG, Section 11.2.2), and of a
//! JPEG image, from its start-of-frame segment (ITU-T T.81, Annex B.2.2).

use super::Dimensions;

/// The PNG signature (PNG, Section 5.2).
pub(super) const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

/// The JPEG start-of-image marker and the first byte of the next marker.
pub(super) const JPEG_SOI: [u8; 3] = [0xff, 0xd8, 0xff];

/// Why a PNG or JPEG image gives no dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RasterFault {
    /// The PNG has no IHDR chunk of 13 bytes after its signature.
    PngHeader,
    /// The JPEG ends, or reaches its scan, before a start-of-frame segment.
    JpegFrame,
}

impl RasterFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::PngHeader => "png_header",
            Self::JpegFrame => "jpeg_frame",
        }
    }
}

siros_codec::display_code!(RasterFault);

impl std::error::Error for RasterFault {}

/// The width and height of the PNG `bytes`.
pub(super) fn png(bytes: &[u8]) -> Result<Option<Dimensions>, RasterFault> {
    let part = |range: std::ops::Range<usize>| bytes.get(range).ok_or(RasterFault::PngHeader);
    if part(8..12)? != [0, 0, 0, 13] || part(12..16)? != b"IHDR" {
        return Err(RasterFault::PngHeader);
    }
    Ok(Some(Dimensions {
        width: u32_be(part(16..20)?),
        height: u32_be(part(20..24)?),
    }))
}

/// The width and height of the JPEG `bytes`: those of its first start-of-frame segment.
pub(super) fn jpeg(bytes: &[u8]) -> Result<Option<Dimensions>, RasterFault> {
    let mut at = 2;
    loop {
        // Fill bytes precede a marker (Annex B.1.1.2).
        while bytes.get(at) == Some(&0xff) && bytes.get(at + 1) == Some(&0xff) {
            at += 1;
        }
        let (Some(0xff), Some(&marker)) = (bytes.get(at), bytes.get(at + 1)) else {
            return Err(RasterFault::JpegFrame);
        };
        at += 2;
        // Markers without a segment: TEM and RST0 to RST7.
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = bytes
            .get(at..at + 2)
            .map(|b| usize::from(u16_be(b)))
            .ok_or(RasterFault::JpegFrame)?;
        if is_start_of_frame(marker) {
            let part = |from: usize| bytes.get(from..from + 2).ok_or(RasterFault::JpegFrame);
            let (height, width) = (u16_be(part(at + 3)?), u16_be(part(at + 5)?));
            return Ok(Some(Dimensions {
                width: u32::from(width),
                height: u32::from(height),
            }));
        }
        // Start of scan: the frame header comes before it (Annex B.2.1).
        if marker == 0xda || length < 2 {
            return Err(RasterFault::JpegFrame);
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
