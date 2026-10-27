//! The image rules of PaSO View, Section 3: Data URLs of PNG, JPEG and SVG in base64, `https`
//! URLs pinned by an `#integrity` sibling and fetched through the host with at most 3
//! redirects, 512 KiB and 2048 pixels, the URLs an SVG document references pinned in their
//! fragments, and what the scan of an SVG document cannot vouch for refused (PaSO Proof
//! SD-JWT-VC and SVG, Section 3); and the cap on the items shown, counted before any fetch.

use serde_json::json;
use siros_oid4vp::{HttpStatus, HttpsUrl, MediaType, Redirects};
use siros_transaction_data::{
    ClaimIndex, Dimensions, FetchFault, ImageFault, ImageFormat, Incompatibility, IntegrityFault,
    Location, LocationStep, PayloadFault, RenderFault, ResourceKind, Selection, SvgFault,
    ValueFault, MAX_IMAGE_BYTES,
};

use crate::common::{
    b64, configured, credential, entries, ok, png, query, rows, sri, Documents, Host, Shown, CARD,
};

const TYPE: &str = "urn:paso:sca:com.example:logo:1";

/// A JPEG of `width` by `height` pixels: an APP0 segment, then a baseline start of frame.
fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xd8, 0xff, 0xe0, 0x00, 0x04, 0x4a, 0x46];
    bytes.extend_from_slice(&[0xff, 0xc0, 0x00, 0x0b, 0x08]);
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[0x01, 0x01, 0x11, 0x00]);
    bytes
}

/// An SVG document of `width` by `height`, holding `inner`.
fn svg(width: u32, height: u32, inner: &str) -> Vec<u8> {
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{width}" height="{height}">{inner}</svg>"#
    )
    .into_bytes()
}

fn data(media_type: &str, bytes: &[u8]) -> String {
    format!("data:{media_type};base64,{}", b64(bytes))
}

/// The rows the card shows for a logo of `logo`, its `#integrity` sibling `integrity`, with the
/// host answering fetches with `documents`.
fn outcome(logo: &str, integrity: Option<&str>, documents: Documents) -> Shown {
    let definition = json!({"claims": [
        {"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}
    ]});
    let mut host = Host::new(json!([configured(TYPE, CARD, &definition)]));
    host.images = documents;
    let mut payload = json!({"logo": logo});
    if let Some(integrity) = integrity {
        payload["logo#integrity"] = json!(integrity);
    }
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": payload});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    rows(&host, &entries[0], &credential(CARD, &[]))
}

fn shown(format: ImageFormat) -> Shown {
    Ok(vec![("Logo".to_owned(), format!("<image {format:?}>"))])
}

fn logo() -> Location {
    Location::new(vec![LocationStep::Key("logo".to_owned())])
}

/// A fault of the reference itself, found as the payload conforms.
fn reference(fault: ImageFault) -> Shown {
    Err(Incompatibility::Payload(PayloadFault::Value(
        ClaimIndex::new(0),
        logo(),
        ValueFault::Image(fault),
    )))
}

/// A fault of the image, found as it is verified.
fn image(fault: ImageFault) -> Shown {
    Err(Incompatibility::Image(logo(), fault))
}

#[test]
fn each_image_rule_is_refused_alone() {
    const URL: &str = "https://cdn.example/logo.png";
    const PART: &str = "https://cdn.example/part.png";
    let served = |bytes: &[u8]| vec![(URL.to_owned(), ok(bytes))];
    let pinned = |bytes: &[u8]| format!("{PART}#{}", sri(bytes).replace('=', "%3D"));
    let part = png(1, 1);
    let rows: Vec<(&str, String, Option<String>, Documents, Shown)> = vec![
        (
            "a PNG Data URL",
            data("image/png", &png(10, 10)),
            None,
            vec![],
            shown(ImageFormat::Png),
        ),
        (
            "a JPEG Data URL",
            data("image/jpeg", &jpeg(10, 20)),
            None,
            vec![],
            shown(ImageFormat::Jpeg),
        ),
        (
            "an SVG Data URL",
            data("image/svg+xml", &svg(10, 10, "")),
            None,
            vec![],
            shown(ImageFormat::Svg),
        ),
        (
            "a PNG of 2048 by 2048",
            data("image/png", &png(2048, 2048)),
            None,
            vec![],
            shown(ImageFormat::Png),
        ),
        (
            "a GIF Data URL",
            data("image/gif", b"GIF89a"),
            None,
            vec![],
            reference(ImageFault::DataUrl),
        ),
        (
            "a Data URL without base64",
            "data:image/png,abc".to_owned(),
            None,
            vec![],
            reference(ImageFault::DataUrl),
        ),
        (
            "a Data URL that is no base64",
            "data:image/png;base64,***".to_owned(),
            None,
            vec![],
            reference(ImageFault::Base64(
                siros_codec::base64::decode("***").unwrap_err(),
            )),
        ),
        (
            "a Data URL over 512 KiB",
            format!("data:image/png;base64,{}", "A".repeat(MAX_IMAGE_BYTES + 4)),
            None,
            vec![],
            reference(ImageFault::TooLarge(MAX_IMAGE_BYTES + 4)),
        ),
        (
            "a PNG 2049 pixels wide",
            data("image/png", &png(2049, 1)),
            None,
            vec![],
            image(ImageFault::TooManyPixels(Dimensions {
                width: 2049,
                height: 1,
            })),
        ),
        (
            "a JPEG 2049 pixels high",
            data("image/jpeg", &jpeg(1, 2049)),
            None,
            vec![],
            image(ImageFault::TooManyPixels(Dimensions {
                width: 1,
                height: 2049,
            })),
        ),
        (
            "an SVG 3000 pixels wide",
            data("image/svg+xml", &svg(3000, 10, "")),
            None,
            vec![],
            image(ImageFault::TooManyPixels(Dimensions {
                width: 3000,
                height: 10,
            })),
        ),
        (
            "a JPEG declared PNG",
            data("image/png", &jpeg(1, 1)),
            None,
            vec![],
            image(ImageFault::FormatMismatch(ImageFormat::Png)),
        ),
        (
            "an http URL",
            "http://cdn.example/logo.png".to_owned(),
            None,
            vec![],
            reference(ImageFault::NotHttps),
        ),
        (
            "an https URL without #integrity",
            URL.to_owned(),
            None,
            vec![],
            reference(ImageFault::IntegrityAbsent),
        ),
        (
            "an https URL, pinned and served",
            URL.to_owned(),
            Some(sri(&png(5, 5))),
            served(&png(5, 5)),
            shown(ImageFormat::Png),
        ),
        (
            "content that does not match its pin",
            URL.to_owned(),
            Some(sri(&png(5, 5))),
            served(&png(6, 6)),
            image(ImageFault::Integrity(IntegrityFault::Mismatch)),
        ),
        (
            "a fetch the host answers with 404",
            URL.to_owned(),
            Some(sri(&png(5, 5))),
            vec![],
            image(ImageFault::Fetch(FetchFault::Status(HttpStatus::new(404)))),
        ),
        (
            "an SVG referencing a pinned resource",
            data(
                "image/svg+xml",
                &svg(10, 10, &format!(r#"<image href="{}"/>"#, pinned(&part))),
            ),
            None,
            vec![(PART.to_owned(), ok(&part))],
            shown(ImageFormat::Svg),
        ),
        (
            "an SVG referencing an unpinned resource",
            data(
                "image/svg+xml",
                &svg(10, 10, &format!(r#"<image xlink:href="{PART}"/>"#)),
            ),
            None,
            vec![],
            image(ImageFault::Svg(SvgFault::ReferenceUnpinned(
                PART.to_owned(),
            ))),
        ),
        (
            "an SVG referencing a resource that does not match its pin",
            data(
                "image/svg+xml",
                &svg(
                    10,
                    10,
                    &format!(r#"<rect style="fill: url('{}')"/>"#, pinned(&part)),
                ),
            ),
            None,
            vec![(PART.to_owned(), ok(&png(2, 2)))],
            image(ImageFault::Svg(SvgFault::ReferenceIntegrity(
                pinned(&part),
                IntegrityFault::Mismatch,
            ))),
        ),
        (
            "an XML document that is no SVG",
            data("image/svg+xml", b"<html/>"),
            None,
            vec![],
            image(ImageFault::Svg(SvgFault::NotSvg)),
        ),
    ];
    for (case, logo, integrity, documents, expected) in rows {
        assert_eq!(
            outcome(&logo, integrity.as_deref(), documents),
            expected,
            "{case}"
        );
    }
}

/// The view carries the verified bytes, and those of each resource an SVG document references,
/// by the URL a renderer requests and the kind the host serves it as; a resource fetch accepts
/// the resource types.
#[test]
fn the_view_carries_the_verified_bytes() {
    let part = png(1, 1);
    let reference = format!("https://cdn.example/part.png#{}", sri(&part));
    let document = svg(10, 10, &format!(r#"<image href="{reference}"/>"#));
    let definition = json!({"claims": [
        {"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}
    ]});
    let mut host = Host::new(json!([configured(TYPE, CARD, &definition)]));
    host.images = vec![("https://cdn.example/part.png".to_owned(), ok(&part))];
    let entry = json!({"type": TYPE, "credential_ids": ["card"],
                       "payload": {"logo": data("image/svg+xml", &document)}});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    let (selection, fetches) = host.select_fetching(&[&entries[0]], &credential(CARD, &[]));
    let selection = selection.unwrap();
    let siros_transaction_data::RowValue::Image(image) =
        crate::common::taken(&selection).view().rows()[0].value()
    else {
        panic!("no image")
    };
    assert_eq!(image.bytes(), document.as_slice());
    let [resource] = image.resources() else {
        panic!("{:?}", image.resources())
    };
    assert_eq!(resource.bytes(), part);
    assert_eq!(resource.kind(), ResourceKind::Png);
    assert_eq!(
        resource.url(),
        &HttpsUrl::parse("https://cdn.example/part.png").unwrap()
    );
    let [fetch] = fetches.as_slice() else {
        panic!("{fetches:?}")
    };
    assert_eq!(fetch.accept(), MediaType::RESOURCES);
}

/// An image fetch accepts the image types and follows at most 3 redirects (PaSO View, Section
/// 3, `image`).
#[test]
fn an_image_fetch_follows_at_most_three_redirects() {
    let definition = json!({"claims": [
        {"path": ["logo"], "value_type": "image", "display": [{"locale": "en", "name": "Logo"}]}
    ]});
    let mut host = Host::new(json!([configured(TYPE, CARD, &definition)]));
    let logo = png(5, 5);
    host.images = vec![("https://cdn.example/logo.png".to_owned(), ok(&logo))];
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": {
        "logo": "https://cdn.example/logo.png", "logo#integrity": sri(&logo)}});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    let (selection, fetches) = host.select_fetching(&[&entries[0]], &credential(CARD, &[]));
    assert!(matches!(selection, Ok(Selection::Takes(_))));
    let [fetch] = fetches.as_slice() else {
        panic!("{fetches:?}")
    };
    assert_eq!(fetch.redirects(), Redirects::at_most(3));
    assert_eq!(fetch.accept(), MediaType::IMAGES);
}

/// An entry over the cap of 200 items is refused before any image is fetched (PaSO View,
/// Section 2).
#[test]
fn the_cap_comes_before_any_fetch() {
    let definition = json!({"claims": [
        {"path": ["items", null, "logo"], "value_type": "image",
         "display": [{"locale": "en", "name": "Logo"}]}
    ]});
    let host = Host::new(json!([configured(TYPE, CARD, &definition)]));
    let logo = png(1, 1);
    let items: Vec<_> = (0..250)
        .map(|i| json!({"logo": format!("https://img.example/{i}.png"), "logo#integrity": sri(&logo)}))
        .collect();
    let entry = json!({"type": TYPE, "credential_ids": ["card"], "payload": {"items": items}});
    let entries = entries(&[entry.to_string()], &query(&["card"], CARD));
    let (selection, fetches) = host.select_fetching(&[&entries[0]], &credential(CARD, &[]));
    assert_eq!(fetches, []);
    assert_eq!(
        selection,
        Ok(Selection::Excluded(vec![(
            siros_transaction_data::EntryPosition::new(0),
            Incompatibility::Render(RenderFault::TooManyItems(250))
        )]))
    );
}
