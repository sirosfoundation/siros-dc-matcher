//! The entry set of an offer (K3, K4): an entry per credential, each carrying the offer, its
//! Credential Query and its `credentialId`, with the delegation A9 gives the offer.

use android_credman::{
    AnyEntry, C8String, C8StringExt, DelegationType, EntrySet, Field, Payment, PaymentDisplay,
    SetEntry, SetSink, Shown, Slot, VerificationDisplay,
};
use siros_credential::Instance;
use siros_display::purpose;
use siros_presentation::{
    Choice, DisplayFacts, HostDisplay, Offer, OfferIndex, Pick, Presentability, Rows,
    TransactionData, Transactions, WalletDisplay,
};
use siros_transaction_data::Deferral;

use crate::fields::{PaymentShown, TransactionShown};
use crate::shown::{Emitted, ShownOffer};

/// Prefix of the set ids: offer `n` is the set `siros-n`.
///
/// A set is a group of entries the picker selects together. Each set holds the members of one
/// offer, which the user presents as a unit; the alternative offers are separate sets.
const SET_PREFIX: &str = "siros";

/// The level the host reported (`GetWasmVersion`), which decides what it shows of an entry
/// (`display_skipped`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostLevel(u32);

impl HostLevel {
    /// The level `credman` reported.
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn reported(credman: &android_credman::Credman) -> Self {
        Self(credman.level())
    }

    /// What the host shows of `entry`.
    fn shows(self, entry: &SetEntry<'_, AnyEntry<'_>>) -> HostDisplay {
        match entry.shown(self.0) {
            Shown::Full => HostDisplay::Full,
            Shown::Skipped => HostDisplay::Skipped,
        }
    }
}

/// The transaction data the entries are made with, and the level of the host they are for.
pub(crate) struct OfferEntries<'a> {
    pub(crate) transactions: &'a Transactions<Deferral>,
    pub(crate) level: HostLevel,
}

/// An entry's text as host strings, owned while its set is emitted.
struct HostEntry<'a> {
    cred_id: C8String,
    title: C8String,
    subtitle: C8String,
    disclaimer: Option<C8String>,
    data: C8String,
    icon: &'a [u8],
    fields: Vec<HostField>,
    payment: Option<HostPayment>,
}

/// A field's label and value as host strings.
struct HostField {
    name: C8String,
    value: Option<C8String>,
}

/// A payment entry's text as host strings.
struct HostPayment {
    merchant: C8String,
    amount: C8String,
    additional_info: Option<C8String>,
}

impl OfferEntries<'_> {
    /// Emits the entry set of `shown`, shown as the offer at `at`, to `sets`: an entry per
    /// credential of its members, in order, each in its own slot, each carrying its pick (K3).
    ///
    /// # Panics
    ///
    /// When `shown` has no credential: the presentation component's offer has a member (DCQL
    /// refuses an empty `credentials` and an empty option), and a member a candidate.
    #[expect(
        clippy::expect_used,
        reason = "an offer without a credential breaks the presentation component's \
                  guarantees, and no entry set the picker could emit for it is right"
    )]
    pub(crate) fn emit(
        &self,
        at: OfferIndex,
        shown: &ShownOffer<'_, Emitted<'_, '_>>,
        sets: &mut impl SetSink,
    ) {
        let offer = shown.offer;
        let emitted = &shown.credentials;
        let disclaimer = purpose::line(offer.purposes());
        let strings: Vec<HostEntry<'_>> = emitted
            .iter()
            .map(|credential| HostEntry::of(at, credential, disclaimer.as_deref()))
            .collect();
        let fields: Vec<Vec<Field<'_>>> = strings.iter().map(HostEntry::fields).collect();
        let entries: Vec<SetEntry<'_, AnyEntry<'_>>> = strings
            .iter()
            .zip(&fields)
            .map(|(strings, fields)| strings.entry(fields))
            .collect();
        let delegation = self.delegation(offer, emitted, &entries);
        let entries: Vec<SetEntry<'_, AnyEntry<'_>>> = entries
            .into_iter()
            .map(|entry| entry.with_delegation(delegation))
            .collect();
        let slots: Vec<Slot<'_, AnyEntry<'_>>> = entries.iter().map(Slot::one).collect();
        // The presentation component's guarantee: an offer has a member, and a member a
        // candidate. Without one, the matching it was built from is wrong.
        let (first, others) = slots
            .split_first()
            .expect("an offer has a member with a candidate");
        let id = C8String::from_str_lossy(&format!("{SET_PREFIX}-{at}"));
        sets.add_entry_set(&EntrySet::new(&id, *first, others));
    }

    /// The delegation of every entry of `offer` (K4): `Full` when the offer needs no wallet
    /// display (A9), judged with the rows the picker shows of `emitted` and what the host shows
    /// of `entries`; none otherwise.
    fn delegation(
        &self,
        offer: &Offer,
        emitted: &[Emitted<'_, '_>],
        entries: &[SetEntry<'_, AnyEntry<'_>>],
    ) -> DelegationType {
        let presented = emitted.iter().map(|credential| &credential.presented);
        let presentable = presented
            .clone()
            .all(|shown| shown.credential.presentability() == Presentability::WithoutUi);
        let facts = DisplayFacts {
            presentability: if presentable {
                Presentability::WithoutUi
            } else {
                Presentability::OnWalletUi
            },
            transaction_data: TransactionData::of(self.transactions),
            additions: Choice::of_additions(offer),
            subsets: Choice::of_subsets(offer),
            rows: Rows::of(presented.flat_map(|shown| &shown.fields)),
            host: HostDisplay::of(entries.iter().map(|entry| self.level.shows(entry))),
        };
        match WalletDisplay::of(&facts) {
            WalletDisplay::NotNeeded => DelegationType::Full,
            WalletDisplay::Needed => DelegationType::NoDelegation,
        }
    }
}

impl<'a> HostEntry<'a> {
    /// The host strings of `emitted`, a credential of the offer shown at `at`, under the
    /// verifier's purpose `disclaimer`.
    fn of(at: OfferIndex, emitted: &'a Emitted<'_, '_>, disclaimer: Option<&str>) -> Self {
        let shown = &emitted.presented;
        let credential = Instance::entry(&shown.credential).credential_id();
        let pick = Pick::new(at, shown.query.clone(), credential);
        let card = shown.credential.card();
        let mut fields: Vec<HostField> = shown.fields.iter().map(HostField::of).collect();
        let payment = match &shown.transaction {
            TransactionShown::Nothing => None,
            TransactionShown::Rows(rows) => {
                fields.extend(rows.iter().map(HostField::of));
                None
            }
            TransactionShown::Payment(payment) => Some(HostPayment::of(payment)),
        };
        Self {
            cred_id: C8String::from_str_lossy(&credential.to_string()),
            title: C8String::from_str_lossy(card.title().as_str()),
            subtitle: C8String::from_str_lossy(card.issuer().as_str()),
            disclaimer: disclaimer.map(C8String::from_str_lossy),
            data: C8String::from_str_lossy(&pick.to_json().to_string()),
            icon: emitted.icon.as_bytes(),
            fields,
            payment,
        }
    }

    fn fields(&self) -> Vec<Field<'_>> {
        self.fields
            .iter()
            .map(|field| Field {
                name: &field.name,
                value: field.value.as_deref(),
            })
            .collect()
    }

    /// The entry: a payment entry for a payment, a verification entry otherwise.
    fn entry<'f>(&'f self, fields: &'f [Field<'f>]) -> SetEntry<'f, AnyEntry<'f>> {
        let kind = match &self.payment {
            Some(payment) => AnyEntry::Payment(Payment {
                display: PaymentDisplay {
                    merchant_name: &payment.merchant,
                    payment_method_name: &self.title,
                    payment_method_subtitle: Some(&self.subtitle),
                    payment_method_icon: self.icon,
                    transaction_amount: &payment.amount,
                    bank_icon: None,
                    payment_provider_icon: None,
                },
                additional_info: payment.additional_info.as_deref(),
            }),
            None => AnyEntry::Verification(VerificationDisplay {
                icon: self.icon,
                title: &self.title,
                subtitle: Some(&self.subtitle),
                disclaimer: self.disclaimer.as_deref(),
                warning: None,
            }),
        };
        SetEntry::new(&self.cred_id, kind)
            .with_data(&self.data)
            .with_fields(fields)
    }
}

impl HostPayment {
    fn of(payment: &PaymentShown) -> Self {
        Self {
            merchant: C8String::from_str_lossy(&payment.payee),
            amount: C8String::from_str_lossy(&payment.amount),
            additional_info: payment
                .additional_info
                .as_deref()
                .map(C8String::from_str_lossy),
        }
    }
}

impl HostField {
    fn of(field: &siros_display::Field) -> Self {
        Self {
            name: C8String::from_str_lossy(field.name().as_str()),
            value: field
                .value()
                .map(|value| C8String::from_str_lossy(value.as_str())),
        }
    }
}
