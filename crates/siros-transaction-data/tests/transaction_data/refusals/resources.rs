//! Resources and Data URLs of an SVG document (PaSO Proof SD-JWT-VC and SVG, Section 3): each
//! passes by its content, a resource once per URL against every integrity value the document
//! gives it, a Data URL read as a renderer reads it and labelled with its content's kind.

use siros_codec::Base64Error;
use siros_transaction_data::{
    DataFault, FontFault, IntegrityFault, ResourceKind, SvgFault, MAX_RESOURCES,
};

use super::svg::{data, outcome, refused, shown, svg, woff2};
use crate::common::{b64, ok, png, sri};

/// The WOFF2 known-tag index of `SVG ` (WOFF2, Section 4.1, Table 1).
const SVG_INDEX: u8 = 36;

/// An OpenType font whose directory lists `CFF ` and `SVG `, each a table of 4 bytes after it.
fn otf_with_svg() -> Vec<u8> {
    let mut font = b"OTTO".to_vec();
    font.extend_from_slice(&[0, 2, 0, 32, 0, 1, 0, 0]); // numTables 2, then the search fields
    for (tag, offset) in [(b"CFF ", 44_u32), (b"SVG ", 48)] {
        font.extend_from_slice(tag);
        font.extend_from_slice(&[0; 4]); // checksum
        font.extend_from_slice(&offset.to_be_bytes());
        font.extend_from_slice(&4_u32.to_be_bytes());
    }
    font.extend_from_slice(&[0; 8]);
    font
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
    let cmap = woff2(0);
    assert_eq!(
        outcome(
            &face(&pinned(font, &cmap)),
            vec![(font.to_owned(), ok(&cmap))]
        ),
        shown()
    );
    assert_eq!(
        outcome(&face(&data("font/woff2", &cmap)), Vec::new()),
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
    let otf = otf_with_svg();
    let otf_data = data("font/otf", &otf);
    let woff2_svg = data("font/woff2", &woff2(SVG_INDEX));
    for (case, source, documents, reference) in [
        (
            "an OpenType Data URL",
            otf_data.clone(),
            Vec::new(),
            otf_data,
        ),
        (
            "a pinned OpenType font",
            pinned(font, &otf),
            vec![(font.to_owned(), ok(&otf))],
            font.to_owned(),
        ),
        ("a WOFF2 Data URL", woff2_svg.clone(), Vec::new(), woff2_svg),
    ] {
        assert_eq!(
            outcome(&face(&source), documents),
            refused(SvgFault::ResourceFont(reference, FontFault::SvgTable)),
            "{case} with SVG glyphs"
        );
    }

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

/// A Data URL passes when a renderer reads from it what the check admitted: its media type
/// names its content's kind, `;base64` ends the media type but for spaces, and `=` pads only a
/// length that is a multiple of 4 (Fetch, Section 4.2.1; Infra, Section 4.2).
#[test]
fn data_urls_name_their_content() {
    let image = |href: &str| svg(&format!(r#"<image width="1" height="1" href="{href}"/>"#));
    let part = png(1, 1);
    let mut polyglot = png(1, 1);
    polyglot.extend_from_slice(b"\0\0\0\x14tEXtc\0<script>1</script>\0\0\0\0");
    let as_svg = data("image/svg+xml", &part);
    let as_html = data("text/html", &part);
    let link = data("text/html", &polyglot);
    for (case, document, reference) in [
        ("an SVG media type", image(&as_svg), as_svg.clone()),
        ("an HTML media type", image(&as_html), as_html.clone()),
        (
            "an HTML media type behind a link",
            svg(&format!(
                r#"<a href="{link}"><rect width="1" height="1"/></a>"#
            )),
            link.clone(),
        ),
    ] {
        assert_eq!(
            outcome(&document, Vec::new()),
            refused(SvgFault::DataReference(
                reference,
                DataFault::MediaType(ResourceKind::Png)
            )),
            "a PNG under {case}"
        );
    }

    // A form feed after `base64` reaches the renderer percent-encoded: the payload is text.
    let fed = format!("data:image/png;base64\u{c},{}", b64(&part));
    let escaped = fed.replace('\u{c}', "\\c ");
    assert_eq!(
        outcome(
            &svg(&format!(r#"<rect style="fill:url({escaped})"/>"#)),
            Vec::new()
        ),
        refused(SvgFault::ResourceType(fed))
    );
    let mut longer = part.clone();
    longer.push(0);
    let encoded = b64(&longer);
    let stray = format!("data:image/png;base64,{}=", &encoded[..encoded.len() - 2]);
    assert_eq!(
        outcome(&image(&stray), Vec::new()),
        refused(SvgFault::DataReference(
            stray.clone(),
            DataFault::Base64(Base64Error::Alphabet(encoded.len() - 2))
        )),
        "a = on a length of {}",
        encoded.len() - 1
    );
}
