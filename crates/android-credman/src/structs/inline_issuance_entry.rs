use crate::{CredmanApply, CredmanContext};
use core::ffi::CStr;
use std::borrow::Cow;

/// Entry that triggers an Inline Issuance flow when the requested credential is missing.
///
/// Required:
/// - `cred_id` must not be empty
/// - `title` must not be empty
#[derive(Debug, Clone)]
pub struct InlineIssuanceEntry<'a> {
    pub cred_id: Cow<'a, CStr>,
    pub title: Cow<'a, CStr>,
    pub icon: Option<Cow<'a, [u8]>>,
    pub subtitle: Option<Cow<'a, CStr>>,
}

impl<'a> InlineIssuanceEntry<'a> {
    pub fn new(cred_id: &'a CStr, title: &'a CStr) -> Self {
        Self::new_cow(Cow::Borrowed(cred_id), Cow::Borrowed(title))
    }

    pub fn new_cow(cred_id: Cow<'a, CStr>, title: Cow<'a, CStr>) -> Self {
        Self {
            cred_id,
            title,
            icon: None,
            subtitle: None,
        }
    }
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for InlineIssuanceEntry<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        ctx.host.add_inline_issuance_entry(self);
    }
}
