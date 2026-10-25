//! What an entry shows, and the standalone entries of the base `credman`
//! module.
//!
//! Every field's type follows its row in `ABI.md`: `&C8Str` where the host
//! needs a string, `Option<&C8Str>` where NULL is accepted and means
//! "absent", `&[u8]` where an image is required and `Option<&[u8]>` where it
//! is optional (NULL with length 0 when absent).

use c8str::C8Str;

/// A display field: a name, and a value the host shows beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    /// The field's label.
    pub name: &'a C8Str,
    /// The value; `None` shows the label alone.
    pub value: Option<&'a C8Str>,
}

/// How a verification entry looks in the picker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationDisplay<'a> {
    /// The image. The host drops an entry whose image is empty.
    pub icon: &'a [u8],
    /// The main line.
    pub title: &'a C8Str,
    /// The second line; `None` omits it.
    pub subtitle: Option<&'a C8Str>,
    /// A note under the entry; `None` omits it. A present, empty note is
    /// drawn as a blank label.
    pub disclaimer: Option<&'a C8Str>,
    /// A highlighted warning under the entry; `None` omits it. A present,
    /// empty warning is drawn as a blank badge.
    pub warning: Option<&'a C8Str>,
}

/// How a payment entry looks in the picker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentDisplay<'a> {
    /// Who is paid.
    pub merchant_name: &'a C8Str,
    /// The card or account paying.
    pub payment_method_name: &'a C8Str,
    /// A second line for the payment method; `None` omits it.
    pub payment_method_subtitle: Option<&'a C8Str>,
    /// The payment method's image.
    pub payment_method_icon: &'a [u8],
    /// The amount, formatted for display.
    pub transaction_amount: &'a C8Str,
    /// The bank's image; `None` omits it.
    pub bank_icon: Option<&'a [u8]>,
    /// The payment provider's image; `None` omits it.
    pub payment_provider_icon: Option<&'a [u8]>,
}

/// A second disclaimer and a link, shown with a verification entry.
///
/// All three are required by the conservative rule: no matcher in the
/// evidence passes NULL to the standalone function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationLink<'a> {
    /// The disclaimer text.
    pub secondary_disclaimer: &'a C8Str,
    /// The link's text.
    pub url_display_text: &'a C8Str,
    /// The link's target.
    pub url_value: &'a C8Str,
}

/// A standalone verification entry (`AddStringIdEntry`), with its fields
/// and an optional verification link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringIdEntry<'a> {
    /// The id the wallet receives when the user picks this entry. The host
    /// attaches fields and links by this id, so it is unique among the
    /// standalone entries of one invocation.
    pub cred_id: &'a C8Str,
    /// What the entry shows.
    pub display: VerificationDisplay<'a>,
    /// Display fields (`AddFieldForStringIdEntry`), in order.
    pub fields: &'a [Field<'a>],
    /// `SetAdditionalDisclaimerAndUrlForVerificationEntry`, sent after the
    /// fields.
    pub link: Option<VerificationLink<'a>>,
}

/// A standalone entry of the superseded integer-id API (`AddEntry`,
/// `AddField`).
///
/// Every string is required by the conservative rule: no matcher in the
/// evidence calls these functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyEntry<'a> {
    /// The id the wallet receives when the user picks this entry.
    pub cred_id: i64,
    /// The image.
    pub icon: &'a [u8],
    /// The main line.
    pub title: &'a C8Str,
    /// The second line.
    pub subtitle: &'a C8Str,
    /// A note under the entry.
    pub disclaimer: &'a C8Str,
    /// A highlighted warning under the entry.
    pub warning: &'a C8Str,
    /// Display fields (`AddField`), in order.
    pub fields: &'a [LegacyField<'a>],
}

/// A display field of a [`LegacyEntry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyField<'a> {
    /// The field's label.
    pub name: &'a C8Str,
    /// The value.
    pub value: &'a C8Str,
}

/// A standalone payment entry (`AddPaymentEntry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentEntry<'a> {
    /// The id the wallet receives when the user picks this entry.
    pub cred_id: &'a C8Str,
    /// What the entry shows.
    pub display: PaymentDisplay<'a>,
}

/// An entry that offers to issue a credential the wallet lacks
/// (`AddInlineIssuanceEntry`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InlineIssuanceEntry<'a> {
    /// The id the wallet receives when the user picks this entry.
    pub cred_id: &'a C8Str,
    /// An image, shown for privileged apps; other apps get their app icon.
    pub icon: Option<&'a [u8]>,
    /// A title, shown for privileged apps; other apps get their app label.
    pub title: Option<&'a C8Str>,
    /// The second line; `None` omits it.
    pub subtitle: Option<&'a C8Str>,
}

/// The registering app's own name and icon (`SelfDeclarePackageInfo`). The
/// host honours it for system apps only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageInfo<'a> {
    /// The name to show for the app.
    pub display_name: &'a C8Str,
    /// The icon to show for the app.
    pub icon: &'a [u8],
}
