//! The texts the host hands back for the core to parse: the refusal of a Request Object over
//! its bound.

#![allow(clippy::unwrap_used)]

use siros_oid4vp::RequestObjectText;

#[test]
fn a_request_object_holds_at_most_its_bound() {
    // P1: at most 256 KiB.
    let limit = 256 * 1024;
    assert!(RequestObjectText::new("a".repeat(limit)).is_ok());
    let refused = RequestObjectText::new("a".repeat(limit + 1)).unwrap_err();
    assert_eq!((refused.size(), refused.limit()), (limit + 1, limit));
}
