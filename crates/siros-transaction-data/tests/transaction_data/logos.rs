//! Logos as drawing programs and icon sets export them pass the static SVG subset (PaSO Proof
//! SD-JWT-VC and SVG, Section 3): a row per family.

use crate::common::png;
use crate::refusals::svg::{data, outcome, shown, woff2};

/// Illustrator CC, "Save As" SVG 1.1: a class style sheet, `enable-background` in a style
/// attribute, a gradient and text.
const ILLUSTRATOR_CC: &str = r##"<?xml version="1.0" encoding="utf-8"?>
<!-- Generator: Adobe Illustrator 24.0.0, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 viewBox="0 0 200 100" style="enable-background:new 0 0 200 100;" xml:space="preserve">
<style type="text/css">
	.st0{fill:url(#SVGID_1_);}
	.st1{fill:#1D1D1B;}
	.st2{font-family:'MyriadPro-Bold';}
</style>
<linearGradient id="SVGID_1_" gradientUnits="userSpaceOnUse" x1="10" y1="50" x2="90" y2="50">
	<stop  offset="0" style="stop-color:#0057B8"/>
	<stop  offset="1" style="stop-color:#FFD700"/>
</linearGradient>
<circle class="st0" cx="50" cy="50" r="40"/>
<text transform="matrix(1 0 0 1 100 60)" class="st1 st2">Shop</text>
</svg>"##;

/// Illustrator CS6, "Save As": a DOCTYPE and the `enable-background` attribute.
const ILLUSTRATOR_CS: &str = r##"<?xml version="1.0" encoding="utf-8"?>
<!-- Generator: Adobe Illustrator 16.0.0, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
	 width="200px" height="100px" viewBox="0 0 200 100" enable-background="new 0 0 200 100" xml:space="preserve">
<g>
	<circle fill="#0057B8" cx="50" cy="50" r="40"/>
</g>
</svg>"##;

/// Inkscape SVG: the Inkscape and Sodipodi editing data.
const INKSCAPE: &str = r##"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!-- Created with Inkscape (http://www.inkscape.org/) -->
<svg width="50mm" height="20mm" viewBox="0 0 50 20" version="1.1" id="svg5" inkscape:version="1.2.2 (b0a8486541, 2022-12-01)" sodipodi:docname="logo.svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape" xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd" xmlns="http://www.w3.org/2000/svg" xmlns:svg="http://www.w3.org/2000/svg">
  <sodipodi:namedview id="namedview7" pagecolor="#ffffff" bordercolor="#666666" borderopacity="1.0" inkscape:document-units="mm" showgrid="false">
    <inkscape:grid type="xygrid" id="grid1"/>
  </sodipodi:namedview>
  <defs id="defs2"/>
  <g inkscape:label="Layer 1" inkscape:groupmode="layer" id="layer1">
    <rect style="fill:#0057b8;stroke-width:0.264583" id="rect234" width="20" height="20" x="0" y="0"/>
  </g>
</svg>"##;

/// Inkscape 0.92, "Plain SVG": RDF metadata.
const INKSCAPE_METADATA: &str = r##"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:cc="http://creativecommons.org/ns#" xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg" width="50mm" height="20mm" viewBox="0 0 50 20" version="1.1" id="svg8">
  <defs id="defs2" />
  <metadata id="metadata5"><rdf:RDF><cc:Work rdf:about=""><dc:format>image/svg+xml</dc:format><dc:type rdf:resource="http://purl.org/dc/dcmitype/StillImage" /><dc:title></dc:title></cc:Work></rdf:RDF></metadata>
  <g id="layer1"><rect style="fill:#0057b8" width="20" height="20" x="0" y="0" /></g>
</svg>"##;

/// Affinity Designer: a DOCTYPE and `serif:id`.
const AFFINITY: &str = r##"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg width="100%" height="100%" viewBox="0 0 120 40" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" xml:space="preserve" xmlns:serif="http://www.serif.com/" style="fill-rule:evenodd;clip-rule:evenodd;stroke-linejoin:round;stroke-miterlimit:2;">
    <g id="Logo" serif:id="Logo"><circle cx="20" cy="20" r="16" style="fill:rgb(0,87,184);"/></g>
</svg>"##;

/// CorelDRAW: a DOCTYPE, its namespace and a `metadata` element.
const CORELDRAW: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<!-- Creator: CorelDRAW -->
<svg xmlns="http://www.w3.org/2000/svg" xml:space="preserve" width="50mm" height="20mm" version="1.1" style="shape-rendering:geometricPrecision; text-rendering:geometricPrecision; image-rendering:optimizeQuality; fill-rule:evenodd; clip-rule:evenodd" viewBox="0 0 5000 2000" xmlns:xlink="http://www.w3.org/1999/xlink" xmlns:xodm="http://www.corel.com/coreldraw/odm/2003">
 <g id="Layer_x0020_1"><metadata id="CorelCorpID_0Corel-Layer"/><rect fill="#0057B8" width="2000" height="2000"/></g>
</svg>"##;

/// Sketch: a shadow filter of `feMorphology`, offset, blur and colour matrix.
const SKETCH: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<svg width="40px" height="40px" viewBox="0 0 40 40" version="1.1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
    <!-- Generator: Sketch 52.6 (67491) - http://www.bohemiancoding.com/sketch -->
    <title>Logo</title>
    <desc>Created with Sketch.</desc>
    <defs>
        <circle id="path-1" cx="20" cy="20" r="16"></circle>
        <filter x="-5%" y="-5%" width="110%" height="110%" filterUnits="objectBoundingBox" id="filter-2">
            <feMorphology radius="1" operator="dilate" in="SourceAlpha" result="shadowSpreadOuter1"></feMorphology>
            <feOffset dx="0" dy="0" in="shadowSpreadOuter1" result="shadowOffsetOuter1"></feOffset>
            <feGaussianBlur stdDeviation="0.5" in="shadowOffsetOuter1" result="shadowBlurOuter1"></feGaussianBlur>
            <feColorMatrix values="0 0 0 0 0   0 0 0 0 0   0 0 0 0 0  0 0 0 0.5 0" type="matrix" in="shadowBlurOuter1"></feColorMatrix>
        </filter>
    </defs>
    <g id="Page-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
        <g id="Oval">
            <use fill="black" fill-opacity="1" filter="url(#filter-2)" xlink:href="#path-1"></use>
            <use fill="#0057B8" fill-rule="evenodd" xlink:href="#path-1"></use>
        </g>
    </g>
</svg>"##;

/// simple-icons: `role="img"` and a title.
const SIMPLE_ICONS: &str = r##"<svg role="img" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><title>Visa</title><path d="M9.112 8.262L5.97 15.758H3.92L2.374 9.775c-.094-.368-.175-.503-.461-.658C1.447 8.864.677 8.627 0 8.479l.046-.217h3.3a.904.904 0 01.894.764l.817 4.338 2.018-5.102z"/></svg>"##;

/// Font Awesome: `aria-hidden`, `focusable`, `role` and custom data.
const FONT_AWESOME: &str = r##"<svg aria-hidden="true" focusable="false" data-prefix="fab" data-icon="cc-visa" class="svg-inline--fa fa-cc-visa" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512"><path fill="currentColor" d="M0 0h576v512H0z"></path></svg>"##;

/// Wikimedia: a `switch` among translations by `systemLanguage`.
const WIKIMEDIA: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 40"><switch><text systemLanguage="de" x="0" y="20">Bank</text><text requiredFeatures="http://www.w3.org/TR/SVG11/feature#Text" x="0" y="20">Bank</text></switch></svg>"##;

/// An older exporter: the root's script, style and zoom attributes.
const BATIK: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" contentScriptType="text/ecmascript" zoomAndPan="magnify" contentStyleType="text/css" preserveAspectRatio="xMidYMid meet" version="1.0" viewBox="0 0 100 40"><rect width="40" height="40" fill="#0057B8"/></svg>"##;

/// Text with the SVG 1.1 text properties, `xml:id`, `xlink:title`, and a link to a fragment.
const TEXT_AND_LINK: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 100 40"><defs><rect xml:id="r" width="4" height="4"/></defs><a href="#r" target="_top"><text x="0" y="20" word-spacing="2" writing-mode="lr" pointer-events="none" kerning="auto">Bank AB</text></a><use xlink:href="#r" xlink:title="r"/></svg>"##;

/// `@charset` and a brand colour in a custom property.
const CSS_VARIABLES: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 40"><style>@charset "UTF-8"; :root{--brand:#0057b8}.a{fill:var(--brand)}</style><rect class="a" width="40" height="40"/></svg>"##;

/// Lighting and turbulence filters.
const LIGHTING: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 40"><filter id="f"><feTurbulence baseFrequency="0.05" numOctaves="2" result="t"/><feDiffuseLighting in="t" surfaceScale="2" lighting-color="#fff"><feDistantLight azimuth="45" elevation="30"/></feDiffuseLighting><feSpecularLighting specularExponent="20"><fePointLight x="1" y="1" z="5"/></feSpecularLighting><feConvolveMatrix order="3" kernelMatrix="0 0 0 0 1 0 0 0 0"/><feDisplacementMap in2="t" scale="2"/><feTile/></filter><rect width="40" height="40" filter="url(#f)"/></svg>"##;

/// A drawing program's export: a class style sheet in `defs`, a gradient the classes paint
/// with, a media query, text and custom data.
const CLASSES: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 120 40" width="120" height="40">
  <defs>
    <style>
      .cls-1 { fill: url(#gradient); }
      .cls-2 { fill: #1d1d1b; font-family: Helvetica, Arial, sans-serif; font-size: 18px; }
      @media (prefers-color-scheme: dark) { .cls-2 { fill: rgb(240 240 240 / 90%); } }
    </style>
    <linearGradient id="gradient" x1="0" y1="0" x2="1" y2="1" gradientUnits="objectBoundingBox">
      <stop offset="0" stop-color="#0057b8"/>
      <stop offset="1" stop-color="#ffd700"/>
    </linearGradient>
  </defs>
  <title>Shop</title>
  <!-- Layer 1 -->
  <g id="Layer_1" data-name="Layer 1">
    <circle class="cls-1" cx="20" cy="20" r="18"/>
    <text class="cls-2" x="44" y="26" xml:space="preserve">Shop</text>
    <path d="M40 34h70" stroke="#1d1d1b" stroke-width="2" transform="translate(0 1)"/>
  </g>
</svg>"##;

#[test]
fn each_exported_logo_is_shown() {
    let figma = format!(
        r##"<svg width="120" height="40" viewBox="0 0 120 40" fill="none" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<g clip-path="url(#clip0)"><g filter="url(#filter0)"><circle cx="20" cy="20" r="16" fill="#0057B8"/></g>
<rect x="44" y="8" width="24" height="24" fill="url(#pattern0)"/></g>
<defs>
<filter id="filter0" x="0" y="0" width="40" height="40" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">
<feFlood flood-opacity="0" result="BackgroundImageFix"/>
<feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0" result="hardAlpha"/>
<feOffset dy="2"/><feGaussianBlur stdDeviation="2"/><feComposite in2="hardAlpha" operator="out"/>
<feBlend mode="normal" in="SourceGraphic" in2="BackgroundImageFix" result="shape"/>
</filter>
<pattern id="pattern0" patternContentUnits="objectBoundingBox" width="1" height="1"><use xlink:href="#image0" transform="scale(0.5)"/></pattern>
<clipPath id="clip0"><rect width="120" height="40" fill="white"/></clipPath>
<image id="image0" width="2" height="2" xlink:href="{}"/>
</defs>
</svg>"##,
        data("image/png", &png(2, 2))
    );
    let embedded_font = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 40"><style>@font-face{{font-family:'Brand';src:url("{}") format("woff2")}}.t{{font-family:'Brand'}}</style><text class="t" x="0" y="20">Bank</text></svg>"#,
        data("application/font-woff2", &woff2())
    );
    let logos: [(&str, &str); 17] = [
        ("Illustrator CC", ILLUSTRATOR_CC),
        ("Illustrator CS with a DOCTYPE", ILLUSTRATOR_CS),
        ("Inkscape SVG", INKSCAPE),
        ("Inkscape with RDF metadata", INKSCAPE_METADATA),
        ("Affinity Designer", AFFINITY),
        ("CorelDRAW", CORELDRAW),
        ("Sketch with a shadow", SKETCH),
        ("simple-icons", SIMPLE_ICONS),
        ("Font Awesome", FONT_AWESOME),
        ("Wikimedia switch", WIKIMEDIA),
        ("Figma with an embedded PNG", &figma),
        ("an embedded WOFF2 font", &embedded_font),
        ("an older exporter's root", BATIK),
        ("text properties and a link", TEXT_AND_LINK),
        ("CSS variables", CSS_VARIABLES),
        ("lighting and turbulence", LIGHTING),
        ("a class style sheet", CLASSES),
    ];
    for (family, logo) in logos {
        assert_eq!(outcome(logo, Vec::new()), shown(), "{family}");
    }
}
