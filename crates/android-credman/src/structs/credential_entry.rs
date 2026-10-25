use crate::{CredmanApply, CredmanContext, CredmanSetContext, PaymentEntry, StringIdEntry};

/// A single credential choice that can be rendered standalone or inside a Set.
#[derive(Debug, Clone)]
pub enum CredentialEntry<'a> {
    StringId(StringIdEntry<'a>),
    Payment(PaymentEntry<'a>),
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for CredentialEntry<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        match self {
            CredentialEntry::StringId(e) => CredmanApply::apply(e, ctx),
            CredentialEntry::Payment(e) => CredmanApply::apply(e, ctx),
        }
    }
}

impl<'a, 'b> CredmanApply<CredmanSetContext<'b>> for CredentialEntry<'a> {
    fn apply(&self, ctx: CredmanSetContext<'b>) {
        match self {
            CredentialEntry::StringId(e) => CredmanApply::apply(e, ctx),
            CredentialEntry::Payment(e) => CredmanApply::apply(e, ctx),
        }
    }
}
