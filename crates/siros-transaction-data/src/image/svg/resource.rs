//! The references of an SVG document (PaSO Proof SD-JWT-VC and SVG, Section 3). A reference is
//! a fragment of the document, a Data URL, or an `https` URL whose fragment carries an
//! integrity value. A Data URL's content and each fetched resource pass by their signature and
//! header: a PNG or JPEG image within the image limits, or a font. A Data URL's media type
//! names its content's kind. The wallet fetches each `https` URL once, without its fragment,
//! and checks its content against every integrity value the document gives it.

use siros_codec::{base64, Base64Error};
use siros_oid4vp::{HttpsUrl, MediaType};

use super::super::font::{FontFault, FontFormat};
use super::super::raster::{self, RasterFault};
use super::super::{image_fetch, strip_prefix_ignore_case, Dimensions, Resource, ResourceKind};
use super::{SvgFault, MAX_RESOURCES};
use crate::fetched;
use crate::fetched::{Fetched, Step};
use crate::integrity::{Integrity, IntegrityFault};

/// Why a Data URL is refused: it gives no content (Fetch, Section 4.2.1, "data: URL
/// processor"), or its media type names another kind than its content's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataFault {
    /// No comma ends the media type.
    Comma,
    /// A `%` starts no escape of two hexadecimal digits.
    Percent,
    /// The payload of a `;base64` Data URL is no base64.
    Base64(Base64Error),
    /// The media type does not name the kind of the content, this one.
    MediaType(ResourceKind),
}

impl DataFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Comma => "data_url_comma",
            Self::Percent => "data_url_percent",
            Self::Base64(fault) => fault.code(),
            Self::MediaType(_) => "data_url_media_type",
        }
    }
}

siros_codec::display_code!(DataFault);

impl std::error::Error for DataFault {}

/// The `https` resources of a document's references, in document order.
pub(super) struct Pins(Vec<Pin>);

/// An `https` URL without its fragment, and each integrity value the references give it, with
/// the first reference that gives it.
struct Pin {
    url: HttpsUrl,
    checks: Vec<(String, Integrity)>,
}

impl Pins {
    /// The resources of `references`, at most [`MAX_RESOURCES`]: a fragment of the document
    /// names none, and a Data URL's content passes in place.
    ///
    /// # Errors
    ///
    /// [`SvgFault`] for a reference of another kind, a Data URL whose content does not pass,
    /// and more resources than [`MAX_RESOURCES`].
    pub(super) fn of(references: &[String]) -> Result<Self, SvgFault> {
        let mut pins: Vec<Pin> = Vec::new();
        for reference in references {
            let trimmed = reference.trim_matches(|c: char| c.is_ascii_whitespace());
            if trimmed.starts_with('#') {
                continue;
            }
            if let Some(rest) = strip_prefix_ignore_case(trimmed, "data:") {
                let refused = |fault| SvgFault::DataReference(reference.clone(), fault);
                let data = DataUrl::read(rest).map_err(refused)?;
                let kind = admit(reference, &data.content)?;
                if !data.names(kind) {
                    return Err(refused(DataFault::MediaType(kind)));
                }
                // The renderer reads the content from the document itself.
                continue;
            }
            let (url, integrity) = pinned(reference, trimmed)?;
            match pins.iter_mut().find(|pin| pin.url == url) {
                Some(pin) => {
                    if !pin.checks.iter().any(|(_, given)| *given == integrity) {
                        pin.checks.push((reference.clone(), integrity));
                    }
                }
                None => pins.push(Pin {
                    url,
                    checks: vec![(reference.clone(), integrity)],
                }),
            }
        }
        if pins.len() > MAX_RESOURCES {
            return Err(SvgFault::TooManyResources(pins.len()));
        }
        Ok(Self(pins))
    }

    /// Each resource, its content fetched and checked; the fetch of a resource while the host
    /// has not given it.
    ///
    /// # Errors
    ///
    /// [`SvgFault`] for a fetch without content, content that matches no integrity value of its
    /// URL, and content that does not pass.
    pub(super) fn fetch(self, fetched: &Fetched) -> Result<Step<Vec<Resource>>, SvgFault> {
        let mut resources = Vec::with_capacity(self.0.len());
        for Pin { url, checks } in self.0 {
            let body = fetched!(fetched
                .body(image_fetch(url.clone(), MediaType::RESOURCES))
                .map_err(|fault| SvgFault::ReferenceFetch(url.clone(), fault))?);
            for (reference, integrity) in &checks {
                integrity
                    .check(body)
                    .map_err(|fault| SvgFault::ReferenceIntegrity(reference.clone(), fault))?;
            }
            let kind = admit(url.as_str(), body)?;
            resources.push(Resource {
                url,
                kind,
                bytes: body.to_vec(),
            });
        }
        Ok(Step::Done(resources))
    }
}

/// The kind of the content `body` of `reference`, by its signature and header: a PNG or JPEG
/// image within the image limits, or a font whose header and table directory read.
///
/// # Errors
///
/// [`SvgFault`] for content of another kind, or whose header does not read.
fn admit(reference: &str, body: &[u8]) -> Result<ResourceKind, SvgFault> {
    let raster = |read: fn(&[u8]) -> Result<Option<Dimensions>, RasterFault>| match read(body)
        .map_err(|fault| SvgFault::ResourceRaster(reference.to_owned(), fault))?
    {
        Some(dimensions) if dimensions.over() => Err(SvgFault::ResourceTooManyPixels(
            reference.to_owned(),
            dimensions,
        )),
        Some(_) | None => Ok(()),
    };
    if body.starts_with(&raster::PNG_SIGNATURE) {
        raster(raster::png).map(|()| ResourceKind::Png)
    } else if body.starts_with(&raster::JPEG_SOI) {
        raster(raster::jpeg).map(|()| ResourceKind::Jpeg)
    } else if let Some(format) = FontFormat::sniff(body) {
        format
            .check(body)
            .map_err(|fault: FontFault| SvgFault::ResourceFont(reference.to_owned(), fault))?;
        Ok(ResourceKind::Font(format))
    } else {
        Err(SvgFault::ResourceType(reference.to_owned()))
    }
}

/// A Data URL as a renderer reads it (Fetch, Section 4.2.1).
struct DataUrl {
    /// The essence of the media type, `type/subtype` in ASCII lower case.
    essence: String,
    content: Vec<u8>,
}

impl DataUrl {
    /// The Data URL of `rest`, its text after `data:`: without ASCII tabs and newlines and
    /// without its fragment, its payload percent-decoded, then base64-decoded when the media
    /// type ends in `;`, spaces and `base64`.
    fn read(rest: &str) -> Result<Self, DataFault> {
        let rest: String = rest
            .chars()
            .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
            .collect();
        let without_fragment = rest.split('#').next().unwrap_or_default();
        let (header, payload) = without_fragment.split_once(',').ok_or(DataFault::Comma)?;
        // The URL parser percent-encodes every other control: only spaces remain to strip.
        let header = header.trim_matches(' ');
        let body = percent_decoded(payload).ok_or(DataFault::Percent)?;
        let content = if base64_header(header) {
            forgiving_base64(&body).map_err(DataFault::Base64)?
        } else {
            body
        };
        let essence = header
            .split(';')
            .next()
            .unwrap_or_default()
            .trim_matches(' ')
            .to_ascii_lowercase();
        Ok(Self { essence, content })
    }

    /// Whether the media type names `kind`: its own for an image; for a font, a `font/` type
    /// or `application/font-woff`, which browsers accept.
    fn names(&self, kind: ResourceKind) -> bool {
        match kind {
            ResourceKind::Png | ResourceKind::Jpeg => self.essence == kind.media_type(),
            ResourceKind::Font(_) => {
                self.essence.starts_with("font/") || self.essence == "application/font-woff"
            }
        }
    }
}

/// Whether the media type `header`, stripped of its surrounding spaces, ends in `;`, spaces and
/// `base64`, without regard to ASCII case.
fn base64_header(header: &str) -> bool {
    header
        .len()
        .checked_sub("base64".len())
        .and_then(|at| header.split_at_checked(at))
        .is_some_and(|(before, last)| {
            last.eq_ignore_ascii_case("base64") && before.trim_end_matches(' ').ends_with(';')
        })
}

/// The bytes of base64 `text` without its ASCII whitespace, its padding optional and only on a
/// length that is a multiple of 4 (Infra, Section 4.2, "forgiving-base64 decode"), with zero
/// trailing bits.
fn forgiving_base64(text: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let mut compact: Vec<u8> = text
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if compact.len() % 4 == 0 {
        let padding = compact
            .iter()
            .rev()
            .take(2)
            .take_while(|&&byte| byte == b'=');
        compact.truncate(compact.len() - padding.count());
    }
    if compact.len() % 4 == 1 {
        return Err(Base64Error::Length);
    }
    if let Some(at) = compact.iter().position(|&byte| byte == b'=') {
        return Err(Base64Error::Alphabet(at));
    }
    while compact.len() % 4 != 0 {
        compact.push(b'=');
    }
    let text = std::str::from_utf8(&compact)
        .map_err(|error| Base64Error::Alphabet(error.valid_up_to()))?;
    base64::decode(text)
}

/// The `https` URL of `trimmed`, the reference `reference` without its surrounding whitespace,
/// without its fragment, and the integrity value its fragment carries, percent-decoded
/// (Section 3, steps 1 and 2).
fn pinned(reference: &str, trimmed: &str) -> Result<(HttpsUrl, Integrity), SvgFault> {
    let (url, fragment) = match trimmed.split_once('#') {
        Some((url, fragment)) => (url, Some(fragment)),
        None => (trimmed, None),
    };
    let url =
        HttpsUrl::parse(url).ok_or_else(|| SvgFault::ReferenceNotHttps(reference.to_owned()))?;
    let fragment = fragment.ok_or_else(|| SvgFault::ReferenceUnpinned(reference.to_owned()))?;
    let integrity = percent_decoded(fragment)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(IntegrityFault::Malformed)
        .and_then(|text| Integrity::parse(&text))
        .map_err(|fault| SvgFault::ReferenceIntegrity(reference.to_owned(), fault))?;
    Ok((url, integrity))
}

/// The bytes of `text` with each `%XX` decoded; `None` for a `%` without two hexadecimal
/// digits.
fn percent_decoded(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: Option<&u8>| char::from(*byte?).to_digit(16);
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%' {
            let value = digit(tail.first())? * 16 + digit(tail.get(1))?;
            bytes.push(u8::try_from(value).ok()?);
            rest = tail.get(2..)?;
        } else {
            bytes.push(first);
            rest = tail;
        }
    }
    Some(bytes)
}
