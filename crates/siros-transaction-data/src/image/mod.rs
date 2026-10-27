//! Images of a payload (PaSO View, Section 3, `image`): a Data URL of a PNG, JPEG or SVG image,
//! or an `https` URL whose content a `#integrity` sibling pins. The wallet fetches the content
//! through the host, following at most 3 redirects, verifies it, and the view carries the
//! verified bytes. A TS12 logo may be a URL without `#integrity` (EC TS12 v1.0.1, Section
//! 4.3.1): it cannot be verified.

mod raster;
mod svg;

use siros_codec::json::Json;
use siros_codec::{base64, Base64Error};
use siros_oid4vp::{BodyLimit, Fetch, HttpsUrl, MediaType, Redirects};

use crate::fetched;
use crate::fetched::{FetchFault, Fetched, Step};
use crate::integrity::{Integrity, IntegrityFault};

pub use raster::RasterFault;
pub use svg::SvgFault;

/// The most bytes of an image: of a Data URL's payload, or of the fetched content.
pub const MAX_IMAGE_BYTES: usize = 512 * 1024;

/// The most pixels of an image in either direction.
pub const MAX_IMAGE_PIXELS: u32 = 2048;

/// The limit of an image fetch.
const IMAGE_LIMIT: BodyLimit = BodyLimit::bytes(MAX_IMAGE_BYTES);

/// The most redirects an image fetch follows (PaSO View, Section 3, `image`).
const IMAGE_REDIRECTS: Redirects = Redirects::at_most(3);

/// The fetch of the image or resource at `url`: the image types accepted, at most `limit`
/// bytes, at most 3 redirects.
pub(crate) fn image_fetch(url: HttpsUrl, limit: BodyLimit) -> Fetch {
    Fetch::get(url, MediaType::IMAGES, limit).following(IMAGE_REDIRECTS)
}

/// The pixels of an image in each direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dimensions {
    /// The width.
    pub width: u32,
    /// The height.
    pub height: u32,
}

impl Dimensions {
    /// Whether the image is over [`MAX_IMAGE_PIXELS`] in a direction.
    fn over(self) -> bool {
        self.width > MAX_IMAGE_PIXELS || self.height > MAX_IMAGE_PIXELS
    }
}

/// An image format the wallet shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageFormat {
    /// `image/png`.
    Png,
    /// `image/jpeg`.
    Jpeg,
    /// `image/svg+xml`, rendered statically.
    Svg,
}

impl ImageFormat {
    const ALL: [Self; 3] = [Self::Png, Self::Jpeg, Self::Svg];

    /// The media type.
    #[must_use]
    pub fn media_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Svg => "image/svg+xml",
        }
    }

    pub(crate) fn of_media_type(media_type: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|format| format.media_type().eq_ignore_ascii_case(media_type))
    }

    /// The format of `bytes` by their signature: PNG and JPEG by their magic numbers, else an
    /// SVG document.
    fn sniff(bytes: &[u8]) -> Self {
        if bytes.starts_with(&raster::PNG_SIGNATURE) {
            Self::Png
        } else if bytes.starts_with(&raster::JPEG_SOI) {
            Self::Jpeg
        } else {
            Self::Svg
        }
    }
}

/// Where an image is: a Data URL's bytes, an `https` URL with the integrity metadata its
/// content must match, or, for a TS12 logo, a reference that cannot be verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRef {
    /// A Data URL (RFC 2397) of a PNG, JPEG or SVG image in base64.
    Data {
        /// The declared format.
        format: ImageFormat,
        /// The decoded bytes.
        bytes: Vec<u8>,
    },
    /// An `https` URL and its `#integrity` sibling.
    Remote {
        /// The URL.
        url: HttpsUrl,
        /// The integrity metadata (W3C SRI).
        integrity: Integrity,
    },
    /// A TS12 logo that cannot be verified, and why: the view leaves it out (PaSO Proof
    /// SD-JWT-VC and SVG, Section 2: "considered absent").
    Unverifiable {
        /// The reference, as the payload writes it.
        reference: String,
        /// Why it cannot be verified.
        cause: ImageFault,
    },
}

/// An image whose bytes the wallet verified: within the limits, of its format, and with each
/// resource an SVG document references fetched and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedImage {
    format: ImageFormat,
    bytes: Vec<u8>,
    resources: Vec<Resource>,
}

/// A resource an SVG document references, verified against the integrity value of its URL's
/// fragment (PaSO Proof SD-JWT-VC and SVG, Section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// The URL, as the document writes it.
    pub reference: String,
    /// The verified bytes.
    pub bytes: Vec<u8>,
}

/// Why an image is refused. The entry is then not compatible (PaSO View, Section 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageFault {
    /// The URL is neither a Data URL nor an `https` URL.
    NotHttps,
    /// The `https` URL has no `#integrity` sibling.
    IntegrityAbsent,
    /// The `#integrity` sibling is no string.
    IntegrityNotString,
    /// The integrity metadata does not read, or the content does not match it.
    Integrity(IntegrityFault),
    /// The Data URL has no comma, no `;base64`, or a media type other than PNG, JPEG and SVG.
    DataUrl,
    /// The Data URL's payload is no base64.
    Base64(Base64Error),
    /// The image has this many bytes, more than 512 KiB.
    TooLarge(usize),
    /// The fetch gave no content.
    Fetch(FetchFault),
    /// The bytes are not of the declared format.
    FormatMismatch(ImageFormat),
    /// The PNG or JPEG does not read.
    Raster(RasterFault),
    /// The SVG document does not read, or a resource it references is refused.
    Svg(SvgFault),
    /// The image is over 2048 pixels in a direction.
    TooManyPixels(Dimensions),
}

impl ImageFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotHttps => "image_not_https",
            Self::IntegrityAbsent => "image_integrity_absent",
            Self::IntegrityNotString => "image_integrity_not_string",
            Self::Integrity(fault) => fault.code(),
            Self::DataUrl => "image_data_url",
            Self::Base64(_) => "image_base64",
            Self::TooLarge(_) => "image_too_large",
            Self::Fetch(fault) => fault.code(),
            Self::FormatMismatch(_) => "image_format_mismatch",
            Self::Raster(fault) => fault.code(),
            Self::Svg(fault) => fault.code(),
            Self::TooManyPixels(_) => "image_too_many_pixels",
        }
    }
}

siros_codec::display_code!(ImageFault);

impl std::error::Error for ImageFault {}

impl ImageRef {
    /// The image of a TS12 logo `text`, `integrity` the value of its `#integrity` sibling: a
    /// reference [`ImageRef::parse`] refuses cannot be verified.
    pub(crate) fn logo(text: &str, integrity: Option<&Json>) -> Self {
        Self::parse(text, integrity).unwrap_or_else(|cause| Self::Unverifiable {
            reference: text.to_owned(),
            cause,
        })
    }

    /// The image of the payload string `text`, `integrity` the value of its `#integrity`
    /// sibling.
    pub(crate) fn parse(text: &str, integrity: Option<&Json>) -> Result<Self, ImageFault> {
        if let Some(rest) = strip_prefix_ignore_case(text, "data:") {
            return data_url(rest);
        }
        let url = HttpsUrl::parse(text).ok_or(ImageFault::NotHttps)?;
        let integrity = match integrity {
            None => return Err(ImageFault::IntegrityAbsent),
            Some(Json::String(value)) => Integrity::parse(value).map_err(ImageFault::Integrity)?,
            Some(_) => return Err(ImageFault::IntegrityNotString),
        };
        Ok(Self::Remote { url, integrity })
    }

    /// The image, verified; the fetch of its content or of a resource it references while the
    /// host has not given it.
    ///
    /// # Errors
    ///
    /// [`ImageFault`]: the first rule the image breaks.
    pub(crate) fn verify(&self, fetched: &Fetched) -> Result<Step<VerifiedImage>, ImageFault> {
        let (format, bytes) = match self {
            Self::Data { format, bytes } => (*format, bytes.clone()),
            Self::Remote { url, integrity } => {
                let body = fetched!(fetched
                    .body_of(image_fetch(url.clone(), IMAGE_LIMIT))
                    .map_err(ImageFault::Fetch)?);
                integrity.check(body).map_err(ImageFault::Integrity)?;
                (ImageFormat::sniff(body), body.to_vec())
            }
            Self::Unverifiable { cause, .. } => return Err(cause.clone()),
        };
        if ImageFormat::sniff(&bytes) != format {
            return Err(ImageFault::FormatMismatch(format));
        }
        let (dimensions, resources) = match format {
            ImageFormat::Png => (raster::png(&bytes).map_err(ImageFault::Raster)?, Vec::new()),
            ImageFormat::Jpeg => (
                raster::jpeg(&bytes).map_err(ImageFault::Raster)?,
                Vec::new(),
            ),
            ImageFormat::Svg => {
                let document = fetched!(svg::read(&bytes, fetched).map_err(ImageFault::Svg)?);
                (document.size, document.resources)
            }
        };
        if let Some(dimensions) = dimensions.filter(|d| d.over()) {
            return Err(ImageFault::TooManyPixels(dimensions));
        }
        Ok(Step::Done(VerifiedImage {
            format,
            bytes,
            resources,
        }))
    }
}

impl VerifiedImage {
    /// The format.
    #[must_use]
    pub fn format(&self) -> ImageFormat {
        self.format
    }

    /// The verified bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The resources an SVG document references, each verified.
    #[must_use]
    pub fn resources(&self) -> &[Resource] {
        &self.resources
    }
}

/// The image of a Data URL's text after `data:`: `<media type>[;<parameter>]*;base64,<data>`,
/// the payload at most 512 KiB.
fn data_url(rest: &str) -> Result<ImageRef, ImageFault> {
    let (header, payload) = rest.split_once(',').ok_or(ImageFault::DataUrl)?;
    let mut parts = header.split(';');
    let format = parts
        .next()
        .and_then(ImageFormat::of_media_type)
        .ok_or(ImageFault::DataUrl)?;
    if !parts
        .next_back()
        .is_some_and(|last| last.eq_ignore_ascii_case("base64"))
    {
        return Err(ImageFault::DataUrl);
    }
    if payload.len() > MAX_IMAGE_BYTES {
        return Err(ImageFault::TooLarge(payload.len()));
    }
    let bytes = base64::decode(payload).map_err(ImageFault::Base64)?;
    Ok(ImageRef::Data { format, bytes })
}

/// `text` after `prefix`, compared without regard to ASCII case.
pub(crate) fn strip_prefix_ignore_case<'t>(text: &'t str, prefix: &str) -> Option<&'t str> {
    text.get(..prefix.len())
        .filter(|start| start.eq_ignore_ascii_case(prefix))
        .and_then(|_| text.get(prefix.len()..))
}
