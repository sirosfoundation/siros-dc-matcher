use crate::{CredmanApply, CredmanContext};
use core::ffi::CStr;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct VerificationEntryUpdate<'a> {
    pub cred_id: Cow<'a, CStr>,
    pub secondary_disclaimer: Option<Cow<'a, CStr>>,
    pub url_display_text: Option<Cow<'a, CStr>>,
    pub url_value: Option<Cow<'a, CStr>>,
}

impl<'a> VerificationEntryUpdate<'a> {
    pub fn new(cred_id: &'a CStr) -> Self {
        Self::new_cow(Cow::Borrowed(cred_id))
    }

    pub fn new_cow(cred_id: Cow<'a, CStr>) -> Self {
        Self {
            cred_id,
            secondary_disclaimer: None,
            url_display_text: None,
            url_value: None,
        }
    }
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for VerificationEntryUpdate<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        ctx.host
            .set_additional_disclaimer_and_url_for_verification_entry(self);
    }
}
