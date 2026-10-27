//! SVG documents (PaSO Proof SD-JWT-VC and SVG, Section 3): every URL the document references
//! carries its integrity value in its fragment, and the wallet fetches and verifies each. The
//! scan vouches for every reference: what it cannot read — a processing instruction, a
//! `foreignObject`, a CSS escape, a CSS function that takes a URL as a string, a Data URL other
//! than a PNG or JPEG image — refuses the document. A document's size is its root's `width` and
//! `height` in absolute units.

use siros_oid4vp::{BodyLimit, HttpsUrl};

use super::{
    image_fetch, strip_prefix_ignore_case, Dimensions, ImageFormat, Resource, MAX_IMAGE_BYTES,
};
use crate::fetched;
use crate::fetched::{FetchFault, Fetched, Step};
use crate::integrity::{Integrity, IntegrityFault};

/// The limit of the fetch of a resource an SVG document references.
const RESOURCE_LIMIT: BodyLimit = BodyLimit::bytes(MAX_IMAGE_BYTES);

/// The CSS functions that take a URL as a string, which the scan does not follow.
const STRING_URL_FUNCTIONS: [&str; 2] = ["image-set(", "src("];

/// Why an SVG document is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvgFault {
    /// The bytes are no UTF-8 text.
    NotUtf8,
    /// The text is no XML document without a DTD.
    Xml(roxmltree::Error),
    /// The root element is no `svg` element.
    NotSvg,
    /// The document holds a processing instruction of this target.
    ProcessingInstruction(String),
    /// The document holds a `foreignObject` element.
    ForeignObject,
    /// An attribute or a `style` element holds a backslash: a CSS escape.
    CssEscape,
    /// CSS calls this function, which takes a URL as a string.
    CssFunction(&'static str),
    /// The document references this Data URL of a type other than PNG and JPEG.
    DataReference(String),
    /// A URL the document references is no `https` URL.
    ReferenceNotHttps(String),
    /// A URL the document references has no fragment.
    ReferenceUnpinned(String),
    /// The fragment of this URL is no integrity value, or its content does not match it.
    ReferenceIntegrity(String, IntegrityFault),
    /// The fetch of this URL gave no content.
    ReferenceFetch(String, FetchFault),
}

impl SvgFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotUtf8 => "svg_not_utf8",
            Self::Xml(_) => "svg_xml",
            Self::NotSvg => "svg_root",
            Self::ProcessingInstruction(_) => "svg_processing_instruction",
            Self::ForeignObject => "svg_foreign_object",
            Self::CssEscape => "svg_css_escape",
            Self::CssFunction(_) => "svg_css_function",
            Self::DataReference(_) => "svg_data_reference",
            Self::ReferenceNotHttps(_) => "svg_reference_not_https",
            Self::ReferenceUnpinned(_) => "svg_reference_unpinned",
            Self::ReferenceIntegrity(..) => "svg_reference_integrity",
            Self::ReferenceFetch(..) => "svg_reference_fetch",
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
    let document = roxmltree::Document::parse(text).map_err(SvgFault::Xml)?;
    let root = document.root_element();
    if root.tag_name().name() != "svg" {
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
    let mut resources = Vec::new();
    for reference in references(&document)? {
        let (url, integrity) = pinned(&reference)?;
        let body = fetched!(fetched
            .body(image_fetch(url, RESOURCE_LIMIT))
            .map_err(|fault| SvgFault::ReferenceFetch(reference.clone(), fault))?);
        integrity
            .check(body)
            .map_err(|fault| SvgFault::ReferenceIntegrity(reference.clone(), fault))?;
        resources.push(Resource {
            reference,
            bytes: body.to_vec(),
        });
    }
    Ok(Step::Done(Document { size, resources }))
}

/// The URLs `document` references outside itself, in document order, each once: each `href`
/// and `src` attribute, and each `url(…)` and `@import` of an attribute or a `style` element,
/// CSS names compared without regard to ASCII case. A reference to a fragment of the document,
/// and a Data URL of a PNG or JPEG image, are inside it.
///
/// # Errors
///
/// [`SvgFault`]: a construct the scan cannot vouch for.
fn references(document: &roxmltree::Document<'_>) -> Result<Vec<String>, SvgFault> {
    let mut found: Vec<String> = Vec::new();
    for node in document.descendants() {
        if let Some(pi) = node.pi() {
            return Err(SvgFault::ProcessingInstruction(pi.target.to_owned()));
        }
        if !node.is_element() {
            continue;
        }
        if node.tag_name().name().eq_ignore_ascii_case("foreignObject") {
            return Err(SvgFault::ForeignObject);
        }
        for attribute in node.attributes() {
            if matches!(attribute.name(), "href" | "src") {
                found.push(attribute.value().trim().to_owned());
            }
            found.extend(css_urls(attribute.value())?);
        }
        if node.tag_name().name() == "style" {
            let css: String = node.descendants().filter_map(|n| n.text()).collect();
            found.extend(css_urls(&css)?);
        }
    }
    let mut unique: Vec<String> = Vec::new();
    for reference in found {
        if reference.starts_with('#') || inside_data_url(&reference)? || unique.contains(&reference)
        {
            continue;
        }
        unique.push(reference);
    }
    Ok(unique)
}

/// Whether `reference` is a Data URL of a PNG or JPEG image, which holds no reference.
///
/// # Errors
///
/// [`SvgFault::DataReference`] for a Data URL of another type, an SVG document included.
fn inside_data_url(reference: &str) -> Result<bool, SvgFault> {
    let Some(rest) = strip_prefix_ignore_case(reference, "data:") else {
        return Ok(false);
    };
    let media_type = rest.split([';', ',']).next().unwrap_or_default().trim();
    match ImageFormat::of_media_type(media_type) {
        Some(ImageFormat::Png | ImageFormat::Jpeg) => Ok(true),
        Some(ImageFormat::Svg) | None => Err(SvgFault::DataReference(reference.to_owned())),
    }
}

/// The URLs of the `url(…)` functions and `@import` rules of the CSS text `css`, CSS names
/// compared without regard to ASCII case.
///
/// # Errors
///
/// [`SvgFault::CssEscape`] for a backslash, and [`SvgFault::CssFunction`] for a function that
/// takes a URL as a string.
fn css_urls(css: &str) -> Result<Vec<String>, SvgFault> {
    if css.contains('\\') {
        return Err(SvgFault::CssEscape);
    }
    let folded = css.to_ascii_lowercase();
    if let Some(function) = STRING_URL_FUNCTIONS
        .into_iter()
        .find(|function| folded.contains(function))
    {
        return Err(SvgFault::CssFunction(function));
    }
    let unquote = |text: &str| {
        text.trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .trim()
            .to_owned()
    };
    // ASCII case folding keeps every byte offset, so `folded` locates the names in `css`.
    let after = |name: &str| -> Vec<&str> {
        folded
            .match_indices(name)
            .filter_map(|(at, _)| css.get(at + name.len()..))
            .collect()
    };
    let mut urls: Vec<String> = after("url(")
        .into_iter()
        .filter_map(|rest| rest.split(')').next())
        .map(unquote)
        .collect();
    urls.extend(after("@import").into_iter().filter_map(|rest| {
        let rest = rest.trim_start();
        let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
        rest.get(1..)?.split(quote).next().map(str::to_owned)
    }));
    Ok(urls)
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
