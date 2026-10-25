use crate::{CredmanApply, CredmanContext};
use core::ffi::CStr;
use std::borrow::Cow;

/// Package metadata for system-only self-declaration (v4+).
#[derive(Debug, Clone)]
pub struct PackageInfo<'a> {
    pub package_display_name: &'a CStr,
    pub package_icon: Option<Cow<'a, [u8]>>,
}

impl<'a> PackageInfo<'a> {
    pub fn new(package_display_name: &'a CStr) -> Self {
        Self {
            package_display_name,
            package_icon: None,
        }
    }
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for PackageInfo<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        if let Some(v4) = ctx.host.as_v4() {
            v4.self_declare_package_info(self);
        }
    }
}
