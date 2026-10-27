//! Resources of an SVG document (PaSO Proof SD-JWT-VC and SVG, Section 3): each passes by its
//! content, once per URL, against every integrity value the document gives it.

use siros_transaction_data::{FontFault, IntegrityFault, SvgFault, MAX_RESOURCES};

use super::svg::{data, outcome, refused, shown, svg, woff2};
use crate::common::{ok, png, sri};

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
