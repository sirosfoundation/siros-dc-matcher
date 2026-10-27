//! SVG documents (PaSO Proof SD-JWT-VC and SVG, Section 3; PaSO View, Section 3, `image`). A
//! document passes only within a static subset: the elements and attributes of [`allow`], CSS
//! within the subset of `css`, and each URL a same-document fragment, a Data URL of a PNG or
//! JPEG image, or an `https` URL whose fragment carries its integrity value. The wallet fetches
//! and verifies each such resource, at most [`MAX_RESOURCES`], and admits PNG and JPEG images
//! within the image limits and WOFF, WOFF2, TrueType and OpenType fonts. A document's size is
//! its root's `width` and `height` in absolute units.

mod allow;
mod markup;

use roxmltree::{Document as Xml, Node, NodeType, ParsingOptions};
use siros_oid4vp::{BodyLimit, HttpsUrl};

use super::css::{self, CssFault};
use super::raster::{self, RasterFault};
use super::{
    image_fetch, strip_prefix_ignore_case, Dimensions, ImageFormat, Resource, MAX_IMAGE_BYTES,
};
use crate::fetched;
use crate::fetched::{FetchFault, Fetched, Step};
use crate::integrity::{Integrity, IntegrityFault};

pub use markup::MAX_DEPTH;

/// The limit of the fetch of a resource an SVG document references.
const RESOURCE_LIMIT: BodyLimit = BodyLimit::bytes(MAX_IMAGE_BYTES);

/// The most resources an SVG document references. A logo draws from a few images and fonts;
/// each is a fetch at consent time.
pub const MAX_RESOURCES: usize = 8;

/// Why an SVG document is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvgFault {
    /// The bytes are no UTF-8 text.
    NotUtf8,
    /// The document nests elements deeper than [`MAX_DEPTH`] levels.
    Nesting,
    /// The text is no XML document whose DOCTYPE has no internal subset.
    Xml(roxmltree::Error),
    /// The root element is no `svg` element of the SVG namespace.
    NotSvg,
    /// The document holds a processing instruction of this target.
    ProcessingInstruction(String),
    /// The document holds this element, of this namespace, outside the static subset.
    Element(Option<String>, String),
    /// The element of the first name takes no attribute of the second.
    Attribute(String, String),
    /// A `style` element holds something other than text.
    StyleContent,
    /// The CSS of the document breaks the subset.
    Css(CssFault),
    /// The document references this URL, which is neither a fragment of the document, a Data
    /// URL of a PNG or JPEG image, nor an `https` URL.
    ReferenceNotHttps(String),
    /// The document references this `https` URL without a fragment.
    ReferenceUnpinned(String),
    /// The fragment of this URL is no integrity value, or its content does not match it.
    ReferenceIntegrity(String, IntegrityFault),
    /// The fetch of this URL gave no content.
    ReferenceFetch(String, FetchFault),
    /// The document references this Data URL of a type other than PNG and JPEG.
    DataReference(String),
    /// The document references this many resources, more than [`MAX_RESOURCES`].
    TooManyResources(usize),
    /// The content of this URL is neither a PNG or JPEG image nor a font.
    ResourceType(String),
    /// The PNG or JPEG image of this URL does not read.
    ResourceRaster(String, RasterFault),
    /// The PNG or JPEG image of this URL is over 2048 pixels in a direction.
    ResourceTooManyPixels(String, Dimensions),
}

impl SvgFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotUtf8 => "svg_not_utf8",
            Self::Nesting => "svg_nesting",
            Self::Xml(_) => "svg_xml",
            Self::NotSvg => "svg_root",
            Self::ProcessingInstruction(_) => "svg_processing_instruction",
            Self::Element(..) => "svg_element",
            Self::Attribute(..) => "svg_attribute",
            Self::StyleContent => "svg_style_content",
            Self::Css(fault) => fault.code(),
            Self::ReferenceNotHttps(_) => "svg_reference_not_https",
            Self::ReferenceUnpinned(_) => "svg_reference_unpinned",
            Self::ReferenceIntegrity(..) => "svg_reference_integrity",
            Self::ReferenceFetch(..) => "svg_reference_fetch",
            Self::DataReference(_) => "svg_data_reference",
            Self::TooManyResources(_) => "svg_too_many_resources",
            Self::ResourceType(_) => "svg_resource_type",
            Self::ResourceRaster(..) => "svg_resource_raster",
            Self::ResourceTooManyPixels(..) => "svg_resource_too_many_pixels",
        }
    }
}

siros_codec::display_code!(SvgFault);

impl std::error::Error for SvgFault {}

/// An SVG document read: its size when its root states one, and each resource it references,
/// verified.
pub(super) struct Document {
    pub(super) size: Option<Dimensions>,
    pub(super) resources: Vec<Resource>,
}

/// The SVG document `bytes`; the fetch of a resource while the host has not given it.
pub(super) fn read(bytes: &[u8], fetched: &Fetched) -> Result<Step<Document>, SvgFault> {
    let text = std::str::from_utf8(bytes).map_err(|_| SvgFault::NotUtf8)?;
    let options = ParsingOptions {
        allow_dtd: markup::scan(text)?.readable(),
        ..ParsingOptions::default()
    };
    let document = Xml::parse_with_options(text, options).map_err(SvgFault::Xml)?;
    let root = document.root_element();
    if root.tag_name().namespace() != Some(allow::SVG) || root.tag_name().name() != "svg" {
        return Err(SvgFault::NotSvg);
    }
    let size = match (
        length(root.attribute("width")),
        length(root.attribute("height")),
    ) {
        (None, None) => None,
        (width, height) => Some(Dimensions {
            width: width.unwrap_or(0),
            height: height.unwrap_or(0),
        }),
    };
    let mut pinned: Vec<(String, HttpsUrl, Integrity)> = Vec::new();
    for reference in references(&document)? {
        if let Some((url, integrity)) = classify(&reference)? {
            if !pinned.iter().any(|(seen, _, _)| *seen == reference) {
                pinned.push((reference, url, integrity));
            }
        }
    }
    if pinned.len() > MAX_RESOURCES {
        return Err(SvgFault::TooManyResources(pinned.len()));
    }
    let mut resources = Vec::with_capacity(pinned.len());
    for (reference, url, integrity) in pinned {
        let body = fetched!(fetched
            .body(image_fetch(url, RESOURCE_LIMIT))
            .map_err(|fault| SvgFault::ReferenceFetch(reference.clone(), fault))?);
        integrity
            .check(body)
            .map_err(|fault| SvgFault::ReferenceIntegrity(reference.clone(), fault))?;
        admit(&reference, body)?;
        resources.push(Resource {
            reference,
            bytes: body.to_vec(),
        });
    }
    Ok(Step::Done(Document { size, resources }))
}

/// The URLs of every URL position of `document`, in document order: each `href` of an
/// element that takes one, and each URL of its CSS.
///
/// # Errors
///
/// [`SvgFault`]: the first node, attribute or CSS token outside the subset.
fn references(document: &Xml<'_>) -> Result<Vec<String>, SvgFault> {
    let mut found = Vec::new();
    for node in document.root().descendants() {
        match node.node_type() {
            NodeType::Root | NodeType::Comment | NodeType::Text => {}
            NodeType::PI => {
                let target = node
                    .pi()
                    .map_or_else(String::new, |pi| pi.target.to_owned());
                return Err(SvgFault::ProcessingInstruction(target));
            }
            NodeType::Element => found.extend(element(node)?),
        }
    }
    Ok(found)
}

/// The URLs of the element `node`, checked against the subset.
fn element(node: Node<'_, '_>) -> Result<Vec<String>, SvgFault> {
    let tag = node.tag_name();
    let name = tag.name();
    let own = match (tag.namespace(), allow::attributes(name)) {
        (Some(allow::SVG), Some(own)) => own,
        (namespace, _) => {
            return Err(SvgFault::Element(
                namespace.map(str::to_owned),
                name.to_owned(),
            ))
        }
    };
    let mut found = Vec::new();
    for attribute in node.attributes() {
        let refused = || SvgFault::Attribute(name.to_owned(), attribute.name().to_owned());
        match (attribute.namespace(), attribute.name()) {
            (Some(allow::XLINK), "href") | (None, "href") => {
                if !allow::HREF.contains(&name) {
                    return Err(refused());
                }
                found.push(attribute.value().to_owned());
            }
            (Some(allow::XML), "space" | "lang") => {}
            (None, "style") => found.extend(css::urls(attribute.value()).map_err(SvgFault::Css)?),
            // Custom data, which no renderer reads (SVG 2, Section 1.9).
            (None, data) if data.starts_with("data-") => {}
            (None, attribute_name) if allow::takes(name, own, attribute_name) => {
                if allow::PRESENTATION.contains(&attribute_name) {
                    found.extend(css::urls(attribute.value()).map_err(SvgFault::Css)?);
                }
            }
            _ => return Err(refused()),
        }
    }
    if name == "style" {
        let mut sheet = String::new();
        for child in node.children() {
            match (child.node_type(), child.text()) {
                (NodeType::Text, Some(text)) => sheet.push_str(text),
                _ => return Err(SvgFault::StyleContent),
            }
        }
        found.extend(css::urls(&sheet).map_err(SvgFault::Css)?);
    }
    Ok(found)
}

/// The resource `reference` names: `None` for a fragment of the document or a Data URL of a
/// PNG or JPEG image, else its `https` URL and integrity value.
///
/// # Errors
///
/// [`SvgFault`] for a URL of another kind.
fn classify(reference: &str) -> Result<Option<(HttpsUrl, Integrity)>, SvgFault> {
    let trimmed = reference.trim_matches(|c: char| c.is_ascii_whitespace());
    if trimmed.starts_with('#') {
        return Ok(None);
    }
    if let Some(rest) = strip_prefix_ignore_case(trimmed, "data:") {
        let media_type = rest.split([';', ',']).next().unwrap_or_default().trim();
        return match ImageFormat::of_media_type(media_type) {
            Some(ImageFormat::Png | ImageFormat::Jpeg) => Ok(None),
            Some(ImageFormat::Svg) | None => Err(SvgFault::DataReference(reference.to_owned())),
        };
    }
    pinned(trimmed).map(Some)
}

/// The font signatures a resource may carry: WOFF, WOFF2, TrueType and OpenType.
const FONTS: [&[u8]; 5] = [b"wOFF", b"wOF2", &[0, 1, 0, 0], b"true", b"OTTO"];

/// Checks the content `body` of the resource `reference` by its signature: a PNG or JPEG image
/// within the image limits, or a font.
fn admit(reference: &str, body: &[u8]) -> Result<(), SvgFault> {
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
        raster(raster::png)
    } else if body.starts_with(&raster::JPEG_SOI) {
        raster(raster::jpeg)
    } else if FONTS.iter().any(|signature| body.starts_with(signature)) {
        Ok(())
    } else {
        Err(SvgFault::ResourceType(reference.to_owned()))
    }
}

/// The `https` URL of `reference` without its fragment, and the integrity value its fragment
/// carries, percent-decoded (Section 3, steps 1 and 2).
fn pinned(reference: &str) -> Result<(HttpsUrl, Integrity), SvgFault> {
    let (url, fragment) = reference
        .split_once('#')
        .ok_or_else(|| SvgFault::ReferenceUnpinned(reference.to_owned()))?;
    let url =
        HttpsUrl::parse(url).ok_or_else(|| SvgFault::ReferenceNotHttps(reference.to_owned()))?;
    let integrity = percent_decoded(fragment)
        .ok_or(IntegrityFault::Malformed)
        .and_then(|text| Integrity::parse(&text))
        .map_err(|fault| SvgFault::ReferenceIntegrity(reference.to_owned(), fault))?;
    Ok((url, integrity))
}

/// `text` with each `%XX` decoded; `None` for a malformed escape or bytes that are no UTF-8.
fn percent_decoded(text: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut rest = text.as_bytes();
    while let Some((&first, tail)) = rest.split_first() {
        if first == b'%' {
            let hex = std::str::from_utf8(tail.get(..2)?).ok()?;
            bytes.push(u8::from_str_radix(hex, 16).ok()?);
            rest = tail.get(2..)?;
        } else {
            bytes.push(first);
            rest = tail;
        }
    }
    String::from_utf8(bytes).ok()
}

/// The pixels of an SVG length attribute in an absolute unit, rounded up; `None` for an absent
/// attribute, a relative unit, or no number (SVG 1.1, Section 7.10; CSS 96 pixels per inch).
fn length(value: Option<&str>) -> Option<u32> {
    let value = value?.trim();
    let split = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '+' || c == '-' || c == 'e'))
        .unwrap_or(value.len());
    let (number, unit) = value.split_at_checked(split)?;
    let number: f64 = number.parse().ok()?;
    let per_unit = match unit.trim() {
        "" | "px" => 1.0,
        "in" => 96.0,
        "cm" => 96.0 / 2.54,
        "mm" => 96.0 / 25.4,
        "pt" => 96.0 / 72.0,
        "pc" => 16.0,
        _ => return None,
    };
    let pixels = (number * per_unit).ceil();
    if pixels.is_finite() && pixels >= 0.0 {
        // Saturating: a size beyond u32 is over the limit either way.
        Some(if pixels > f64::from(u32::MAX) {
            u32::MAX
        } else {
            pixels as u32
        })
    } else {
        None
    }
}
