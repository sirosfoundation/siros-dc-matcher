use crate::{
    CredmanApply, CredmanContext, CredmanFieldContext, CredmanFieldSetContext, CredmanSetContext,
    Field,
};
use core::ffi::CStr;
use std::borrow::Cow;

/// Standard entry rendered by Credential Manager with a string `cred_id`.
///
/// Required:
/// - `cred_id` must not be empty
/// - `title` must not be empty
///
/// Optional:
/// - `metadata` is forwarded only when rendered inside a set (`credman_v2+`).
#[derive(Debug, Clone)]
pub struct StringIdEntry<'a> {
    pub cred_id: Cow<'a, CStr>,
    pub title: Cow<'a, CStr>,
    pub icon: Option<Cow<'a, [u8]>>,
    pub subtitle: Option<Cow<'a, CStr>>,
    pub disclaimer: Option<Cow<'a, CStr>>,
    pub warning: Option<Cow<'a, CStr>>,
    pub metadata: Option<Cow<'a, CStr>>,
    pub fields: Cow<'a, [Field<'a>]>,
}

impl<'a> StringIdEntry<'a> {
    pub fn new(cred_id: &'a CStr, title: &'a CStr) -> Self {
        Self::new_cow(Cow::Borrowed(cred_id), Cow::Borrowed(title))
    }

    pub fn new_cow(cred_id: Cow<'a, CStr>, title: Cow<'a, CStr>) -> Self {
        Self {
            cred_id,
            title,
            icon: None,
            subtitle: None,
            disclaimer: None,
            warning: None,
            metadata: None,
            fields: Cow::Borrowed(&[]),
        }
    }
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for StringIdEntry<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        ctx.host.add_string_id_entry(self);
        if self.fields.is_empty() {
            let field = Field::new(c"_", None);
            let field_ctx = CredmanFieldContext {
                host: ctx.host,
                cred_id: &self.cred_id,
            };
            field.apply(field_ctx);
            return;
        }
        for field in self.fields.iter() {
            let field_ctx = CredmanFieldContext {
                host: ctx.host,
                cred_id: &self.cred_id,
            };
            field.apply(field_ctx);
        }
    }
}

impl<'a, 'b> CredmanApply<CredmanSetContext<'b>> for StringIdEntry<'a> {
    fn apply(&self, ctx: CredmanSetContext<'b>) {
        ctx.v2.add_entry_to_set(self, ctx.set_id, ctx.set_index);
        if self.fields.is_empty() {
            let field = Field::new(c"_", Some(c"_"));
            let field_ctx = CredmanFieldSetContext {
                v2: ctx.v2,
                cred_id: &self.cred_id,
                set_id: ctx.set_id,
                set_index: ctx.set_index,
            };
            field.apply(field_ctx);
            return;
        }
        for field in self.fields.iter() {
            let field_ctx = CredmanFieldSetContext {
                v2: ctx.v2,
                cred_id: &self.cred_id,
                set_id: ctx.set_id,
                set_index: ctx.set_index,
            };
            field.apply(field_ctx);
        }
    }
}
