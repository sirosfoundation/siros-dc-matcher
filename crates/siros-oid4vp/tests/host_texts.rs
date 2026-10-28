//! The texts the host hands back for the core to parse: one refusal per rule of the Request
//! Object's bound and of the Verifier's reply to a direct post (Section 8.2).

#![allow(clippy::unwrap_used, clippy::panic)]

use siros_oid4vp::{Reply, ReplyFault, RequestObjectText, ResponseError};

#[test]
fn a_request_object_holds_at_most_its_bound() {
    let limit = RequestObjectText::MAX_BYTES;
    assert!(RequestObjectText::new("a".repeat(limit)).is_ok());
    let refused = RequestObjectText::new("a".repeat(limit + 1)).unwrap_err();
    assert_eq!((refused.size(), refused.limit()), (limit + 1, limit));
}

#[test]
fn each_refusal_of_a_reply() {
    let long = format!(r#"{{"a": "{}"}}"#, "a".repeat(Reply::MAX_BYTES));
    let refused = |body: &[u8]| Reply::parse(body).unwrap_err();
    match refused(long.as_bytes()) {
        ResponseError::ReplyUnreadable(ReplyFault::TooLarge(fault)) => {
            assert_eq!(
                (fault.size(), fault.limit()),
                (long.len(), Reply::MAX_BYTES)
            );
        }
        other => panic!("too large, got {other:?}"),
    }
    assert!(matches!(
        refused(b"{"),
        ResponseError::ReplyUnreadable(ReplyFault::NotJson(_))
    ));
    assert_eq!(
        refused(b"[]"),
        ResponseError::ReplyUnreadable(ReplyFault::NotObject)
    );
    assert_eq!(
        refused(br#"{"redirect_uri": "/cb"}"#),
        ResponseError::RedirectUriInvalid
    );
    // A reply without `redirect_uri` asks nothing more of the wallet; other members are ignored.
    assert_eq!(
        Reply::parse(br#"{"response_code": "091535f699ea575c"}"#)
            .unwrap()
            .redirect_uri(),
        None
    );
}
