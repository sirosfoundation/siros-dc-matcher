//! The icons the wallet's writer admits: a PNG or JPEG of 64 to 256 pixels in each direction,
//! the dimensions read from the PNG IHDR chunk (PNG, Section 11.2.2) and the JPEG start-of-frame
//! segment (ITU-T T.81, Annex B.2.2).

use siros_registration::{Dimensions, IconFault, RasterIcon};

/// A PNG's signature and IHDR chunk.
fn png(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR".to_vec();
    bytes.extend(width.to_be_bytes());
    bytes.extend(height.to_be_bytes());
    bytes.extend([8, 2, 0, 0, 0]);
    bytes
}

/// A JPEG's start of image, a JFIF APP0 segment the reader skips, and a baseline SOF0 segment.
fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8];
    bytes.extend([0xff, 0xe0, 0x00, 0x10]);
    bytes.extend(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
    bytes.extend([0xff, 0xc0, 0x00, 0x11, 0x08]);
    bytes.extend(height.to_be_bytes());
    bytes.extend(width.to_be_bytes());
    bytes.extend([0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01]);
    bytes
}

#[test]
fn the_writer_admits_raster_icons_of_64_to_256_pixels() {
    let size = |width, height| Dimensions { width, height };
    let rows: Vec<(&str, Vec<u8>, Result<(), IconFault>)> = vec![
        ("a PNG of 120 by 80 pixels", png(120, 80), Ok(())),
        ("a JPEG of 64 by 64 pixels", jpeg(64, 64), Ok(())),
        (
            "an SVG document",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\"/>".to_vec(),
            Err(IconFault::NotRaster),
        ),
        (
            "a PNG of 4 by 4 pixels",
            png(4, 4),
            Err(IconFault::TooSmall(size(4, 4))),
        ),
        (
            "a JPEG of 512 by 128 pixels",
            jpeg(512, 128),
            Err(IconFault::TooLarge(size(512, 128))),
        ),
        (
            "a PNG cut inside its IHDR chunk",
            png(64, 64)[..20].to_vec(),
            Err(IconFault::PngHeader),
        ),
        (
            "a JPEG without a start-of-frame segment",
            jpeg(64, 64)[..20].to_vec(),
            Err(IconFault::JpegFrame),
        ),
    ];
    for (case, bytes, expected) in rows {
        assert_eq!(RasterIcon::parse(bytes).map(|_| ()), expected, "{case}");
    }
}
