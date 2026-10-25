use crate::{
    CredmanApply, CredmanContext, CredmanFieldContext, CredmanFieldSetContext, CredmanSetContext,
    Field,
};
use core::ffi::CStr;
use std::borrow::Cow;

/// High-fidelity Payment/SCA entry emphasizing merchant and amount.
///
/// Required:
/// - `cred_id` must not be empty
/// - `merchant_name` must not be empty
/// - `transaction_amount` must not be empty and should match the verifier request
///
/// Optional:
/// - `metadata` is forwarded for entries emitted in sets.
/// - `additional_info` is used only with the v3 set API (`AddPaymentEntryToSetV2`).
#[derive(Debug, Clone)]
pub struct PaymentEntry<'a> {
    pub cred_id: Cow<'a, CStr>,
    pub merchant_name: Cow<'a, CStr>,
    pub transaction_amount: Cow<'a, CStr>,
    pub payment_method_name: Option<Cow<'a, CStr>>,
    pub payment_method_subtitle: Option<Cow<'a, CStr>>,
    pub payment_method_icon: Option<Cow<'a, [u8]>>,
    pub bank_icon: Option<Cow<'a, [u8]>>,
    pub payment_provider_icon: Option<Cow<'a, [u8]>>,
    pub metadata: Option<Cow<'a, CStr>>,
    pub additional_info: Option<Cow<'a, CStr>>,
    pub fields: Cow<'a, [Field<'a>]>,
}

impl<'a> PaymentEntry<'a> {
    pub fn new(cred_id: &'a CStr, merchant_name: &'a CStr, transaction_amount: &'a CStr) -> Self {
        Self::new_cow(
            Cow::Borrowed(cred_id),
            Cow::Borrowed(merchant_name),
            Cow::Borrowed(transaction_amount),
        )
    }

    pub fn new_cow(
        cred_id: Cow<'a, CStr>,
        merchant_name: Cow<'a, CStr>,
        transaction_amount: Cow<'a, CStr>,
    ) -> Self {
        Self {
            cred_id,
            merchant_name,
            transaction_amount,
            payment_method_name: None,
            payment_method_subtitle: None,
            payment_method_icon: None,
            bank_icon: None,
            payment_provider_icon: None,
            metadata: None,
            additional_info: None,
            fields: Cow::Borrowed(&[]),
        }
    }

    pub fn add_field(mut self, display_name: &'a CStr, display_value: &'a CStr) -> Self {
        let mut fields = self.fields.into_owned();
        fields.push(Field::new(display_name, Some(display_value)));
        self.fields = Cow::Owned(fields);
        self
    }
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for PaymentEntry<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        ctx.host.add_payment_entry(self);
        apply_payment_fields(
            self,
            CredmanFieldContext {
                host: ctx.host,
                cred_id: &self.cred_id,
            },
        );
    }
}

impl<'a, 'b> CredmanApply<CredmanSetContext<'b>> for PaymentEntry<'a> {
    fn apply(&self, ctx: CredmanSetContext<'b>) {
        if let Some(v3) = ctx.v2.as_v3() {
            v3.add_payment_entry_to_set_v2(self, ctx.set_id, ctx.set_index);
        } else {
            ctx.v2
                .add_payment_entry_to_set(self, ctx.set_id, ctx.set_index);
        }
        apply_payment_fields_in_set(
            self,
            CredmanFieldSetContext {
                v2: ctx.v2,
                cred_id: &self.cred_id,
                set_id: ctx.set_id,
                set_index: ctx.set_index,
            },
        );
    }
}

fn apply_payment_fields(entry: &PaymentEntry<'_>, ctx: CredmanFieldContext<'_>) {
    if entry.fields.is_empty() {
        let field = Field::new(c"_", None);
        field.apply(ctx);
        return;
    }

    for field in entry.fields.iter() {
        field.apply(ctx);
    }
}

fn apply_payment_fields_in_set(entry: &PaymentEntry<'_>, ctx: CredmanFieldSetContext<'_>) {
    if entry.fields.is_empty() {
        let field = Field::new(c"_", Some(c"_"));
        field.apply(ctx);
        return;
    }

    for field in entry.fields.iter() {
        field.apply(ctx);
    }
}
