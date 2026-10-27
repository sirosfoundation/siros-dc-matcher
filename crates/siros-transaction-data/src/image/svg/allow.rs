//! The static SVG subset the wallet shows: the elements of the SVG namespace that draw shapes,
//! text, paint servers, clips, masks, markers and filters without a resource of their own,
//! each with its attributes. Script, animation, `set`, `foreignObject`, fonts, links and every
//! other namespace are outside it, and so are attributes outside each element's set but
//! `data-*`. The sets follow svg-hush's allowlist (Cloudflare) and usvg's static subset,
//! without what draws from another document.

/// The SVG namespace.
pub(super) const SVG: &str = "http://www.w3.org/2000/svg";

/// The XLink namespace, whose `href` is a plain `href`.
pub(super) const XLINK: &str = "http://www.w3.org/1999/xlink";

/// The XML namespace, whose `space` and `lang` pass.
pub(super) const XML: &str = "http://www.w3.org/XML/1998/namespace";

/// The attributes every element of the subset takes.
const CORE: [&str; 4] = ["id", "class", "style", "lang"];

/// The presentation attributes (SVG 2, Section 6.6), every element's; their values are CSS.
pub(super) const PRESENTATION: [&str; 54] = [
    "alignment-baseline",
    "baseline-shift",
    "clip-path",
    "clip-rule",
    "color",
    "color-interpolation",
    "color-interpolation-filters",
    "direction",
    "display",
    "dominant-baseline",
    "fill",
    "fill-opacity",
    "fill-rule",
    "filter",
    "flood-color",
    "flood-opacity",
    "font-family",
    "font-size",
    "font-size-adjust",
    "font-stretch",
    "font-style",
    "font-variant",
    "font-weight",
    "image-rendering",
    "isolation",
    "letter-spacing",
    "lighting-color",
    "marker-end",
    "marker-mid",
    "marker-start",
    "mask",
    "mask-type",
    "mix-blend-mode",
    "opacity",
    "overflow",
    "paint-order",
    "shape-rendering",
    "stop-color",
    "stop-opacity",
    "stroke",
    "stroke-dasharray",
    "stroke-dashoffset",
    "stroke-linecap",
    "stroke-linejoin",
    "stroke-miterlimit",
    "stroke-opacity",
    "stroke-width",
    "text-anchor",
    "text-decoration",
    "text-rendering",
    "transform-origin",
    "unicode-bidi",
    "vector-effect",
    "visibility",
];

/// The elements that take an `href`, a URL position.
pub(super) const HREF: [&str; 6] = [
    "image",
    "linearGradient",
    "pattern",
    "radialGradient",
    "textPath",
    "use",
];

/// The filter primitives' own attributes.
const PRIMITIVE: [&str; 6] = ["x", "y", "width", "height", "result", "in"];

/// Each element of the subset with the attributes of its own.
const ELEMENTS: [(&str, &[&str]); 38] = [
    (
        "svg",
        &[
            "x",
            "y",
            "width",
            "height",
            "viewBox",
            "preserveAspectRatio",
            "version",
            "baseProfile",
        ],
    ),
    ("g", &["transform"]),
    ("defs", &[]),
    ("title", &[]),
    ("desc", &[]),
    ("style", &["type", "media"]),
    (
        "symbol",
        &[
            "x",
            "y",
            "width",
            "height",
            "viewBox",
            "preserveAspectRatio",
            "refX",
            "refY",
        ],
    ),
    ("use", &["x", "y", "width", "height", "transform", "href"]),
    (
        "image",
        &[
            "x",
            "y",
            "width",
            "height",
            "preserveAspectRatio",
            "transform",
            "href",
        ],
    ),
    ("path", &["d", "pathLength", "transform"]),
    (
        "rect",
        &[
            "x",
            "y",
            "width",
            "height",
            "rx",
            "ry",
            "pathLength",
            "transform",
        ],
    ),
    ("circle", &["cx", "cy", "r", "pathLength", "transform"]),
    (
        "ellipse",
        &["cx", "cy", "rx", "ry", "pathLength", "transform"],
    ),
    ("line", &["x1", "y1", "x2", "y2", "pathLength", "transform"]),
    ("polyline", &["points", "pathLength", "transform"]),
    ("polygon", &["points", "pathLength", "transform"]),
    (
        "text",
        &[
            "x",
            "y",
            "dx",
            "dy",
            "rotate",
            "textLength",
            "lengthAdjust",
            "transform",
        ],
    ),
    (
        "tspan",
        &["x", "y", "dx", "dy", "rotate", "textLength", "lengthAdjust"],
    ),
    (
        "textPath",
        &[
            "href",
            "startOffset",
            "method",
            "spacing",
            "side",
            "textLength",
            "lengthAdjust",
        ],
    ),
    ("clipPath", &["clipPathUnits", "transform"]),
    (
        "mask",
        &["x", "y", "width", "height", "maskUnits", "maskContentUnits"],
    ),
    (
        "pattern",
        &[
            "x",
            "y",
            "width",
            "height",
            "patternUnits",
            "patternContentUnits",
            "patternTransform",
            "viewBox",
            "preserveAspectRatio",
            "href",
        ],
    ),
    (
        "marker",
        &[
            "viewBox",
            "preserveAspectRatio",
            "refX",
            "refY",
            "markerUnits",
            "markerWidth",
            "markerHeight",
            "orient",
        ],
    ),
    (
        "linearGradient",
        &[
            "x1",
            "y1",
            "x2",
            "y2",
            "gradientUnits",
            "gradientTransform",
            "spreadMethod",
            "href",
        ],
    ),
    (
        "radialGradient",
        &[
            "cx",
            "cy",
            "r",
            "fx",
            "fy",
            "fr",
            "gradientUnits",
            "gradientTransform",
            "spreadMethod",
            "href",
        ],
    ),
    ("stop", &["offset"]),
    (
        "filter",
        &["x", "y", "width", "height", "filterUnits", "primitiveUnits"],
    ),
    ("feBlend", &["in2", "mode"]),
    ("feColorMatrix", &["type", "values"]),
    ("feComponentTransfer", &[]),
    ("feComposite", &["in2", "operator", "k1", "k2", "k3", "k4"]),
    ("feDropShadow", &["dx", "dy", "stdDeviation"]),
    ("feFlood", &[]),
    (
        "feFuncA",
        &[
            "type",
            "tableValues",
            "slope",
            "intercept",
            "amplitude",
            "exponent",
            "offset",
        ],
    ),
    ("feGaussianBlur", &["stdDeviation", "edgeMode"]),
    ("feMerge", &[]),
    ("feMergeNode", &[]),
    ("feOffset", &["dx", "dy"]),
];

/// The transfer functions, which take the attributes of `feFuncA`.
const TRANSFER: [&str; 3] = ["feFuncB", "feFuncG", "feFuncR"];

/// The attributes of the element `element` of the subset, beside the core and presentation
/// attributes; `None` for an element outside it.
pub(super) fn attributes(element: &str) -> Option<&'static [&'static str]> {
    let element = if TRANSFER.contains(&element) {
        "feFuncA"
    } else {
        element
    };
    ELEMENTS
        .iter()
        .find(|(name, _)| *name == element)
        .map(|(_, own)| *own)
}

/// Whether the element `element` of the subset takes the attribute `name` of no namespace.
pub(super) fn takes(element: &str, own: &[&str], name: &str) -> bool {
    let primitive =
        element.starts_with("fe") && !element.starts_with("feFunc") && element != "feMergeNode";
    CORE.contains(&name)
        || PRESENTATION.contains(&name)
        || own.contains(&name)
        || (primitive && PRIMITIVE.contains(&name))
        || (element == "feMergeNode" && name == "in")
}
