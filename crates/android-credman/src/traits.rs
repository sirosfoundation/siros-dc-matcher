use crate::host::{Credman, CredmanV2, credman};
use core::ffi::CStr;

/// Base context for standalone entry rendering.
#[derive(Clone, Copy)]
pub struct CredmanContext<'a> {
    pub host: &'a dyn Credman,
}

/// Context for entries rendered inside a set.
#[derive(Clone, Copy)]
pub struct CredmanSetContext<'a> {
    pub v2: &'a dyn CredmanV2,
    pub set_id: &'a CStr,
    pub set_index: i32,
}

/// Context for fields rendered on standalone entries.
#[derive(Clone, Copy)]
pub struct CredmanFieldContext<'a> {
    pub host: &'a dyn Credman,
    pub cred_id: &'a CStr,
}

/// Context for fields rendered on set entries.
#[derive(Clone, Copy)]
pub struct CredmanFieldSetContext<'a> {
    pub v2: &'a dyn CredmanV2,
    pub cred_id: &'a CStr,
    pub set_id: &'a CStr,
    pub set_index: i32,
}

/// Emits a value to the host using the Credential Manager output ABI.
///
/// # Purpose
/// Types like `StringIdEntry`, `PaymentEntry`, and `CredentialSet` implement this trait
/// so they can be applied uniformly from matcher code.
pub trait CredmanApply<T> {
    fn apply(&self, options: T);
}

/// Convenience extension for `CredmanApply<CredmanContext>`.
pub trait CredmanRender {
    fn render(&self);
}

impl<S> CredmanRender for S
where
    for<'a> S: CredmanApply<CredmanContext<'a>>,
{
    fn render(&self) {
        let host = credman();
        CredmanApply::apply(self, CredmanContext { host });
    }
}
