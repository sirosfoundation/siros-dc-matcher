use c8str::C8Str;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    pub name: &'a C8Str,
    /// `None` shows the name alone.
    pub value: Option<&'a C8Str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationDisplay<'a> {
    /// The host drops an entry whose icon is empty.
    pub icon: &'a [u8],
    pub title: &'a C8Str,
    pub subtitle: Option<&'a C8Str>,
    /// A note under the entry.
    pub disclaimer: Option<&'a C8Str>,
    /// A highlighted badge under the entry.
    pub warning: Option<&'a C8Str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentDisplay<'a> {
    pub merchant_name: &'a C8Str,
    pub payment_method_name: &'a C8Str,
    pub payment_method_subtitle: Option<&'a C8Str>,
    pub payment_method_icon: &'a [u8],
    pub transaction_amount: &'a C8Str,
    pub bank_icon: Option<&'a [u8]>,
    pub payment_provider_icon: Option<&'a [u8]>,
}

/// A second disclaimer and a link. Every string is required (conservative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationLink<'a> {
    pub secondary_disclaimer: &'a C8Str,
    pub url_display_text: &'a C8Str,
    pub url_value: &'a C8Str,
}

/// `AddStringIdEntry`, then its fields, then its link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringIdEntry<'a> {
    /// Unique among the standalone entries of one invocation: the host
    /// attaches fields and links by it.
    pub cred_id: &'a C8Str,
    pub display: VerificationDisplay<'a>,
    pub fields: &'a [Field<'a>],
    pub link: Option<VerificationLink<'a>>,
}

/// `AddEntry` and its `AddField` fields. Every string is required
/// (conservative).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyEntry<'a> {
    pub cred_id: i64,
    pub icon: &'a [u8],
    pub title: &'a C8Str,
    pub subtitle: &'a C8Str,
    pub disclaimer: &'a C8Str,
    pub warning: &'a C8Str,
    pub fields: &'a [LegacyField<'a>],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyField<'a> {
    pub name: &'a C8Str,
    pub value: &'a C8Str,
}

/// `AddPaymentEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentEntry<'a> {
    pub cred_id: &'a C8Str,
    pub display: PaymentDisplay<'a>,
}

/// `AddInlineIssuanceEntry`: offers to issue a credential the wallet lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InlineIssuanceEntry<'a> {
    pub cred_id: &'a C8Str,
    /// Shown for privileged apps only.
    pub icon: Option<&'a [u8]>,
    /// Shown for privileged apps only.
    pub title: Option<&'a C8Str>,
    pub subtitle: Option<&'a C8Str>,
}

/// `SelfDeclarePackageInfo`, honoured for system apps only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageInfo<'a> {
    pub display_name: &'a C8Str,
    pub icon: &'a [u8],
}
