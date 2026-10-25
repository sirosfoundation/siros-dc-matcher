use c8str::C8Str;

/// A row on an entry naming a value the entry discloses, such as "Age over
/// 21" and "Yes". It follows its entry: [`AddFieldToEntrySet`] in a set,
/// [`AddFieldForStringIdEntry`] on a standalone entry.
///
/// [`AddFieldToEntrySet`]: android_credman_sys::v2::AddFieldToEntrySet
/// [`AddFieldForStringIdEntry`]: android_credman_sys::credman::AddFieldForStringIdEntry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<'a> {
    pub name: &'a C8Str,
    /// `None` shows the name alone.
    pub value: Option<&'a C8Str>,
}

/// How the picker draws a verification entry: one credential the user can
/// present. [`AddEntryToSet`] sends it in a set, [`AddStringIdEntry`]
/// standalone.
///
/// [`AddEntryToSet`]: android_credman_sys::v2::AddEntryToSet
/// [`AddStringIdEntry`]: android_credman_sys::credman::AddStringIdEntry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationDisplay<'a> {
    /// The entry's image, 32×32 pixels or rescaled to it. The host drops an
    /// entry whose icon is empty; a 64×64 PNG shows.
    pub icon: &'a [u8],
    pub title: &'a C8Str,
    /// The line under the title.
    pub subtitle: Option<&'a C8Str>,
    /// A note below the entry.
    pub disclaimer: Option<&'a C8Str>,
    /// A highlighted warning below the entry.
    pub warning: Option<&'a C8Str>,
}

/// How the picker draws a payment entry: a payment the user confirms with a
/// payment credential, such as a card. [`AddPaymentEntryToSet`] sends it in
/// a set, [`AddPaymentEntry`] standalone.
///
/// [`AddPaymentEntryToSet`]: android_credman_sys::v2::AddPaymentEntryToSet
/// [`AddPaymentEntry`]: android_credman_sys::credman::AddPaymentEntry
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentDisplay<'a> {
    /// The payee.
    pub merchant_name: &'a C8Str,
    /// The paying credential's title.
    pub payment_method_name: &'a C8Str,
    pub payment_method_subtitle: Option<&'a C8Str>,
    /// The paying credential's image.
    pub payment_method_icon: &'a [u8],
    /// The amount as display text, such as `EUR 12.00`.
    pub transaction_amount: &'a C8Str,
    /// Where the picker shows it is unconfirmed.
    pub bank_icon: Option<&'a [u8]>,
    /// Where the picker shows it is unconfirmed.
    pub payment_provider_icon: Option<&'a [u8]>,
}

/// A second disclaimer and a link on a verification entry: `url_display_text`
/// is the link's text and `url_value` its target. [`crate::WithLink`] adds it
/// to a set entry, [`StringIdEntry::link`] to a standalone one. How the
/// picker draws it is unconfirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationLink<'a> {
    pub secondary_disclaimer: &'a C8Str,
    pub url_display_text: &'a C8Str,
    pub url_value: &'a C8Str,
}

/// A standalone verification entry with its fields and link, for a host
/// below level 2, which has no sets. [`Host::add_string_id_entry`](crate::Host::add_string_id_entry) sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringIdEntry<'a> {
    /// Comes back to the wallet when the user selects the entry. Unique among
    /// the standalone entries of one invocation: the host attaches fields and
    /// the link by it.
    pub cred_id: &'a C8Str,
    pub display: VerificationDisplay<'a>,
    pub fields: &'a [Field<'a>],
    pub link: Option<VerificationLink<'a>>,
}

/// A standalone entry named by a number, with its fields. Google's header
/// deprecates it for [`StringIdEntry`]. [`Host::add_legacy_entry`](crate::Host::add_legacy_entry) sends it.
/// The display values mean what they mean in [`VerificationDisplay`]; every
/// one is required, a conservative rule, since no known matcher calls it.
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

/// A row on a [`LegacyEntry`], as [`Field`] is on the newer entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegacyField<'a> {
    pub name: &'a C8Str,
    pub value: &'a C8Str,
}

/// A standalone payment entry, for a host below level 2, which has no sets.
/// [`Host::add_payment_entry`](crate::Host::add_payment_entry) sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaymentEntry<'a> {
    /// Comes back to the wallet when the user selects the entry.
    pub cred_id: &'a C8Str,
    pub display: PaymentDisplay<'a>,
}

/// An entry that offers to issue a credential the wallet lacks: on selection
/// the wallet adds the credential and returns it at once (androidx
/// `InlineIssuanceEntry`). [`Host::add_inline_issuance_entry`](crate::Host::add_inline_issuance_entry) sends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InlineIssuanceEntry<'a> {
    /// Comes back to the wallet when the user selects the entry. androidx
    /// limits it to 64 characters.
    pub cred_id: &'a C8Str,
    /// Shown for system-privileged apps only; other apps get the wallet
    /// app's icon.
    pub icon: Option<&'a [u8]>,
    /// Shown for system-privileged apps only; other apps get the wallet
    /// app's label.
    pub title: Option<&'a C8Str>,
    pub subtitle: Option<&'a C8Str>,
}

/// The wallet app's display name and icon, which [`V4::self_declare_package_info`](crate::V4::self_declare_package_info)
/// declares to the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageInfo<'a> {
    pub display_name: &'a C8Str,
    pub icon: &'a [u8],
}
