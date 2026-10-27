//! SVG documents (PaSO Proof SD-JWT-VC and SVG, Section 3; PaSO View, Section 3, `image`). A
//! document passes only within a static subset: its elements nested at most [`MAX_DEPTH`]
//! levels, the elements and attributes of [`allow`], CSS within the subset of `css`, and each
//! URL a same-document fragment, a Data URL, or an `https` URL whose fragment carries its
//! integrity value. The wallet fetches and verifies each such resource, at most
//! [`MAX_RESOURCES`]; a resource and a Data URL's content pass as PNG and JPEG images within the
//! image limits and as WOFF, WOFF2, TrueType and OpenType fonts. A document's size is its
//! root's `width` and `height` in absolute units.

mod allow;
mod length;
mod markup;
mod resource;

use roxmltree::{Attribute, Document as Xml, Node, NodeType, ParsingOptions};
use siros_oid4vp::HttpsUrl;

use super::css::{self, CssFault};
use super::font::FontFault;
use super::raster::RasterFault;
use super::{Dimensions, Resource};
use crate::fetched;
use crate::fetched::{FetchFault, Resources, Step};
use crate::integrity::IntegrityFault;

pub use markup::MAX_DEPTH;
pub use resource::DataFault;

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
    /// The document's DOCTYPE, this declaration, names an external identifier other than a W3C
    /// SVG 1.0 or 1.1 DTD's.
    Doctype(String),
    /// The text is no XML document whose DOCTYPE has no internal subset.
    Xml(roxmltree::Error),
    /// The root element is no `svg` element of the SVG namespace.
    NotSvg,
    /// The document holds a processing instruction of this target.
    ProcessingInstruction(String),
    /// The document holds this element, of this namespace, outside the static subset.
    Element(Option<String>, String),
    /// The element of this name takes no attribute of this namespace and name.
    Attribute {
        /// The element's name.
        element: String,
        /// The attribute's namespace.
        namespace: Option<String>,
        /// The attribute's name.
        name: String,
    },
    /// A `style` element holds something other than text.
    StyleContent,
    /// The CSS of the document breaks the subset.
    Css(CssFault),
    /// The document references this URL, which is neither a fragment of the document, a Data
    /// URL, nor an `https` URL.
    ReferenceNotHttps(String),
    /// The document references this `https` URL without a fragment.
    ReferenceUnpinned(String),
    /// The fragment of this URL is no integrity value, or its content does not match it.
    ReferenceIntegrity(String, IntegrityFault),
    /// The fetch of this URL gave no content.
    ReferenceFetch(HttpsUrl, FetchFault),
    /// The document references this Data URL, which gives no content.
    DataReference(String, DataFault),
    /// The document references this many resources, more than [`MAX_RESOURCES`].
    TooManyResources(usize),
    /// The content of this URL or Data URL is neither a PNG or JPEG image nor a font.
    ResourceType(String),
    /// The PNG or JPEG image of this URL or Data URL does not read.
    ResourceRaster(String, RasterFault),
    /// The PNG or JPEG image of this URL or Data URL is over 2048 pixels in a direction.
    ResourceTooManyPixels(String, Dimensions),
    /// The font of this URL or Data URL has a header or table directory that does not read.
    ResourceFont(String, FontFault),
}

impl SvgFault {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotUtf8 => "svg_not_utf8",
            Self::Nesting => "svg_nesting",
            Self::Doctype(_) => "svg_doctype",
            Self::Xml(_) => "svg_xml",
            Self::NotSvg => "svg_root",
            Self::ProcessingInstruction(_) => "svg_processing_instruction",
            Self::Element(..) => "svg_element",
            Self::Attribute { .. } => "svg_attribute",
            Self::StyleContent => "svg_style_content",
            Self::Css(fault) => fault.code(),
            Self::ReferenceNotHttps(_) => "svg_reference_not_https",
            Self::ReferenceUnpinned(_) => "svg_reference_unpinned",
            Self::ReferenceIntegrity(..) => "svg_reference_integrity",
            Self::ReferenceFetch(..) => "svg_reference_fetch",
            Self::DataReference(..) => "svg_data_reference",
            Self::TooManyResources(_) => "svg_too_many_resources",
            Self::ResourceType(_) => "svg_resource_type",
            Self::ResourceRaster(..) => "svg_resource_raster",
            Self::ResourceTooManyPixels(..) => "svg_resource_too_many_pixels",
            Self::ResourceFont(..) => "svg_resource_font",
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
pub(super) fn read(bytes: &[u8], fetched: &impl Resources) -> Result<Step<Document>, SvgFault> {
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
        length::pixels(root.attribute("width")),
        length::pixels(root.attribute("height")),
    ) {
        (None, None) => None,
        (width, height) => Some(Dimensions {
            width: width.unwrap_or(0),
            height: height.unwrap_or(0),
        }),
    };
    let pins = resource::Pins::of(&references(&document)?)?;
    let resources = fetched!(pins.fetch(fetched)?);
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

/// What an element of a document is to the subset.
#[derive(Clone, Copy)]
enum Kind {
    /// An element of the subset, with the attributes of its own.
    Svg(&'static [&'static str]),
    /// Editing data, or RDF inside a `metadata` element, which renderers ignore.
    Inert,
}

/// The kind of the element `node`.
///
/// # Errors
///
/// [`SvgFault::Element`] for an element outside the subset.
fn kind(node: Node<'_, '_>) -> Result<Kind, SvgFault> {
    let tag = node.tag_name();
    match (tag.namespace(), allow::attributes(tag.name())) {
        (Some(allow::SVG), Some(own)) => Ok(Kind::Svg(own)),
        (Some(namespace), _) if allow::editor(namespace) => Ok(Kind::Inert),
        (Some(namespace), _) if allow::metadata(namespace) && node.ancestors().any(is_metadata) => {
            Ok(Kind::Inert)
        }
        (namespace, _) => Err(SvgFault::Element(
            namespace.map(str::to_owned),
            tag.name().to_owned(),
        )),
    }
}

/// Whether `node` is a `metadata` element of the SVG namespace.
fn is_metadata(node: Node<'_, '_>) -> bool {
    node.tag_name().namespace() == Some(allow::SVG) && node.tag_name().name() == "metadata"
}

/// The URLs of the element `node`, checked against the subset.
fn element(node: Node<'_, '_>) -> Result<Vec<String>, SvgFault> {
    let kind = kind(node)?;
    let name = node.tag_name().name();
    let mut found = Vec::new();
    for attribute in node.attributes() {
        found.extend(self::attribute(kind, name, &attribute)?);
    }
    if matches!(kind, Kind::Svg(_)) && name == "style" {
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

/// The URLs of `attribute` of an element of the name `element` and of `kind`, checked against
/// the subset.
fn attribute(
    kind: Kind,
    element: &str,
    attribute: &Attribute<'_, '_>,
) -> Result<Vec<String>, SvgFault> {
    let refused = || SvgFault::Attribute {
        element: element.to_owned(),
        namespace: attribute.namespace().map(str::to_owned),
        name: attribute.name().to_owned(),
    };
    let scanned = |value: &str| css::urls(value).map_err(SvgFault::Css);
    match (attribute.namespace(), attribute.name()) {
        (Some(allow::XLINK), "href") | (None, "href") => match kind {
            Kind::Svg(_) if allow::HREF.contains(&element) => {
                Ok(vec![attribute.value().to_owned()])
            }
            Kind::Svg(_) | Kind::Inert => Err(refused()),
        },
        (Some(allow::XLINK), "title") | (Some(allow::XML), "space" | "lang" | "id") => {
            Ok(Vec::new())
        }
        (Some(namespace), name) if allow::editor(namespace) && allow::editing(name) => {
            Ok(Vec::new())
        }
        (Some(namespace), _) if matches!(kind, Kind::Inert) && allow::metadata(namespace) => {
            Ok(Vec::new())
        }
        (None, "style") => scanned(attribute.value()),
        // Custom data and accessibility states, which no renderer draws (SVG 2, Section 1.9).
        (None, name) if name.starts_with("data-") || name.starts_with("aria-") => Ok(Vec::new()),
        (None, name) => {
            let taken = match kind {
                Kind::Svg(own) => allow::takes(element, own, name),
                Kind::Inert => true,
            };
            match (taken, allow::PRESENTATION.contains(&name)) {
                (false, _) => Err(refused()),
                (true, true) => scanned(attribute.value()),
                (true, false) => Ok(Vec::new()),
            }
        }
        (Some(_), _) => Err(refused()),
    }
}

