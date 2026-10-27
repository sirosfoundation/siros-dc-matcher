//! The static SVG subset the wallet shows: the elements of the SVG namespace that draw shapes,
//! text, paint servers, clips, masks, markers and filters without a resource of their own, with
//! links, `switch` and `metadata`, each with its attributes. Drawing programs' editing data
//! passes: the elements and attributes of their namespaces, and RDF metadata inside `metadata`.
//! Script, animation, `set`, `foreignObject`, `feImage`, fonts, XHTML and every other namespace
//! are outside it, and so are attributes outside each element's set but `data-*` and `aria-*`.
//! The sets follow svg-hush's allowlist (Cloudflare) and usvg's static subset, without what
//! draws from another document.

/// The SVG namespace.
pub(super) const SVG: &str = "http://www.w3.org/2000/svg";

/// The XLink namespace, whose `href` is a plain `href`.
pub(super) const XLINK: &str = "http://www.w3.org/1999/xlink";

/// The XML namespace, whose `space`, `lang` and `id` pass.
pub(super) const XML: &str = "http://www.w3.org/XML/1998/namespace";

/// The namespaces of drawing programs' editing data, which renderers ignore: Inkscape,
/// Sodipodi, Affinity (Serif) and CorelDRAW. Their elements pass, and their attributes but
/// those of [`EDITOR_REFUSED`] and the presentation attributes' names.
const EDITORS: [&str; 4] = [
    "http://www.inkscape.org/namespaces/inkscape",
    "http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd",
    "http://www.serif.com/",
    "http://www.corel.com/coreldraw/odm/2003",
];

/// The local names of editing-data attributes that hold a URL or CSS, refused in the editors'
/// namespaces as everywhere else.
const EDITOR_REFUSED: [&str; 3] = ["href", "absref", "style"];

/// The vocabularies of the RDF inside a `metadata` element: RDF, Dublin Core and Creative
/// Commons, in its current and its former namespace. There, their elements and attributes pass.
const METADATA: [&str; 4] = [
    "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
    "http://purl.org/dc/elements/1.1/",
    "http://creativecommons.org/ns#",
    "http://web.resource.org/cc/",
];

/// The attributes every element of the subset takes: the core attributes, the ARIA role and
/// focus attributes, and the conditional processing attributes, which select among the children
/// of a `switch` (SVG 1.1, Section 5.8).
const CORE: [&str; 10] = [
    "id",
    "class",
    "style",
    "lang",
    "role",
    "tabindex",
    "focusable",
    "systemLanguage",
    "requiredFeatures",
    "requiredExtensions",
];

/// The presentation attributes, every element's; their values are CSS: those of SVG 1.1,
/// Appendix M.2, but `color-profile`, whose IRI value stands outside a CSS `url()`, and those
/// SVG 2, Section 6.6, adds.
pub(super) const PRESENTATION: [&str; 64] = [
    "alignment-baseline",
    "baseline-shift",
    "clip",
    "clip-path",
    "clip-rule",
    "color",
    "color-interpolation",
    "color-interpolation-filters",
    "color-rendering",
    "cursor",
    "direction",
    "display",
    "dominant-baseline",
    "enable-background",
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
    "glyph-orientation-horizontal",
    "glyph-orientation-vertical",
    "image-rendering",
    "isolation",
    "kerning",
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
    "pointer-events",
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
    "word-spacing",
    "writing-mode",
];

/// The elements that take an `href`, a URL position.
pub(super) const HREF: [&str; 7] = [
    "a",
    "image",
    "linearGradient",
    "pattern",
    "radialGradient",
    "textPath",
    "use",
];

/// The filter primitives but `feImage`, which take the primitive attributes.
const PRIMITIVES: [&str; 16] = [
    "feBlend",
    "feColorMatrix",
    "feComponentTransfer",
    "feComposite",
    "feConvolveMatrix",
    "feDiffuseLighting",
    "feDisplacementMap",
    "feDropShadow",
    "feFlood",
    "feGaussianBlur",
    "feMerge",
    "feMorphology",
    "feOffset",
    "feSpecularLighting",
    "feTile",
    "feTurbulence",
];

/// The filter primitives' own attributes.
const PRIMITIVE: [&str; 6] = ["x", "y", "width", "height", "result", "in"];

/// Each element of the subset with the attributes of its own.
const ELEMENTS: [(&str, &[&str]); 51] = [
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
            "contentScriptType",
            "contentStyleType",
            "zoomAndPan",
        ],
    ),
    ("g", &["transform"]),
    ("switch", &["transform"]),
    ("a", &["href", "target", "transform"]),
    ("defs", &[]),
    ("metadata", &[]),
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
    (
        "feConvolveMatrix",
        &[
            "order",
            "kernelMatrix",
            "divisor",
            "bias",
            "targetX",
            "targetY",
            "edgeMode",
            "kernelUnitLength",
            "preserveAlpha",
        ],
    ),
    (
        "feDiffuseLighting",
        &["surfaceScale", "diffuseConstant", "kernelUnitLength"],
    ),
    (
        "feDisplacementMap",
        &["in2", "scale", "xChannelSelector", "yChannelSelector"],
    ),
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
    ("feMergeNode", &["in"]),
    ("feMorphology", &["operator", "radius"]),
    ("feOffset", &["dx", "dy"]),
    (
        "feSpecularLighting",
        &[
            "surfaceScale",
            "specularConstant",
            "specularExponent",
            "kernelUnitLength",
        ],
    ),
    ("feTile", &[]),
    (
        "feTurbulence",
        &["baseFrequency", "numOctaves", "seed", "stitchTiles", "type"],
    ),
    ("feDistantLight", &["azimuth", "elevation"]),
    ("fePointLight", &["x", "y", "z"]),
    (
        "feSpotLight",
        &[
            "x",
            "y",
            "z",
            "pointsAtX",
            "pointsAtY",
            "pointsAtZ",
            "specularExponent",
            "limitingConeAngle",
        ],
    ),
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
    CORE.contains(&name)
        || PRESENTATION.contains(&name)
        || own.contains(&name)
        || (PRIMITIVES.contains(&element) && PRIMITIVE.contains(&name))
}

/// Whether `namespace` is that of a drawing program's editing data.
pub(super) fn editor(namespace: &str) -> bool {
    EDITORS.contains(&namespace)
}

/// Whether the attribute `name` of an editor's namespace passes: neither a URL position nor CSS.
pub(super) fn editing(name: &str) -> bool {
    !EDITOR_REFUSED.contains(&name) && !PRESENTATION.contains(&name)
}

/// Whether `namespace` is a vocabulary of the RDF inside a `metadata` element.
pub(super) fn metadata(namespace: &str) -> bool {
    METADATA.contains(&namespace)
}
