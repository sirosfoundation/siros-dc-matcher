//! The entry set of an offer (K3, K4): an entry per credential, each carrying the offer, its
//! Credential Query and its `credentialId`, with the delegation A9 gives the offer.

use android_credman::{
    AnyEntry, C8String, C8StringExt, DelegationType, EntrySet, Field, Payment, PaymentDisplay,
    SetEntry, SetSink, Shown, Slot, VerificationDisplay,
};
use siros_credential::Instance;
use siros_display::{purpose, Extent};
use siros_presentation::{
    Answer, Answered, Answers, Choice, DisplayFacts, HostDisplay, Offer, OfferIndex, Pick,
    Presentability, Rows, TransactionData, Transactions, WalletDisplay,
};
use siros_registration::RegisteredCredential;
use siros_transaction_data::{Deferral, Selection};

use crate::diagnostics::Unshown;
use crate::fields::{PaymentShown, TransactionShown};
use crate::matching::NoChoice;

/// Prefix of the set ids: offer `n` is the set `siros-n`.
///
/// A set is a group of entries the picker selects together. Each set holds the members of one
/// offer, which the user presents as a unit; the alternative offers are separate sets.
const SET_PREFIX: &str = "siros";

/// The matching the entries are made from.
pub(crate) struct OfferEntries<'a, 'r> {
    answered: &'a Answered<'r, &'a RegisteredCredential, NoChoice>,
    transactions: &'a Transactions<Deferral>,
    level: u32,
}

/// One credential of an offer as its entry shows it.
struct Presented<'a> {
    credential: &'a RegisteredCredential,
    pick: Pick,
    fields: Vec<siros_display::Field>,
    transaction: TransactionShown,
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

impl<'a, 'r> OfferEntries<'a, 'r> {
    /// The entries of the offers of `answered`, whose transaction data `transactions`
    /// selected, for a host at `level`.
    pub(crate) fn sources(
        answered: &'a Answered<'r, &'a RegisteredCredential, NoChoice>,
        transactions: &'a Transactions<Deferral>,
        level: u32,
    ) -> Self {
        Self {
            answered,
            transactions,
            level,
        }
    }

    /// Emits the entry set of `offer`, the offer at `at`, to `sets`: an entry per candidate of
    /// each member, in order, each in its own slot.
    ///
    /// # Errors
    ///
    /// [`Unshown`] for an offer whose rows the registration cannot show.
    pub(crate) fn emit(
        &self,
        at: usize,
        offer: &Offer,
        sets: &mut impl SetSink,
    ) -> Result<(), Unshown> {
        let index = OfferIndex::new(at);
        let shown = self.shown(index, offer)?;
        let disclaimer = purpose::line(offer.purposes());
        let strings: Vec<HostEntry<'_>> = shown
            .iter()
            .map(|shown| HostEntry::of(shown, disclaimer.as_deref()))
            .collect();
        let fields: Vec<Vec<Field<'_>>> = strings.iter().map(HostEntry::fields).collect();
        let entries: Vec<SetEntry<'_, AnyEntry<'_>>> = strings
            .iter()
            .zip(&fields)
            .map(|(strings, fields)| strings.entry(fields))
            .collect();
        let delegation = self.delegation(offer, &shown, &entries);
        let entries: Vec<SetEntry<'_, AnyEntry<'_>>> = entries
            .into_iter()
            .map(|entry| entry.with_delegation(delegation))
            .collect();
        let slots: Vec<Slot<'_, AnyEntry<'_>>> = entries.iter().map(Slot::one).collect();
        let (first, others) = slots.split_first().ok_or(Unshown::Empty(index))?;
        let id = C8String::from_str_lossy(&format!("{SET_PREFIX}-{at}"));
        sets.add_entry_set(&EntrySet::new(&id, *first, others));
        Ok(())
    }

    /// Each candidate of each member of `offer`, the offer at `index`, as its entry shows it.
    fn shown(&self, index: OfferIndex, offer: &Offer) -> Result<Vec<Presented<'a>>, Unshown> {
        offer
            .members()
            .iter()
            .flat_map(|member| {
                let answers = self.answered.answers(member.query());
                member.candidates().iter().map(move |&candidate| {
                    let answers = answers.ok_or(Unshown::Inconsistent(index))?;
                    let selection = self.transactions.selection(member.query(), candidate);
                    let candidate = answers
                        .candidate(candidate)
                        .ok_or(Unshown::Inconsistent(index))?;
                    let credential: &'a RegisteredCredential = candidate.credential();
                    Ok(Presented {
                        credential,
                        pick: Pick::new(
                            index,
                            answers.id().clone(),
                            Instance::entry(&credential).credential_id(),
                        ),
                        fields: fields(index, answers, credential, candidate.answer())?,
                        transaction: match selection {
                            Some(Selection::Takes(taken)) => TransactionShown::of(taken),
                            Some(Selection::Deferred(..) | Selection::Excluded(_)) | None => {
                                TransactionShown::Nothing
                            }
                        },
                    })
                })
            })
            .collect()
    }

    /// The delegation of every entry of `offer` (K4): `Full` when the offer needs no wallet
    /// display (A9), judged with the rows the picker shows and what the host shows of
    /// `entries`; none otherwise.
    fn delegation(
        &self,
        offer: &Offer,
        shown: &[Presented<'_>],
        entries: &[SetEntry<'_, AnyEntry<'_>>],
    ) -> DelegationType {
        let presentable = shown
            .iter()
            .all(|shown| shown.credential.presentability() == Presentability::WithoutUi);
        let whole = shown
            .iter()
            .flat_map(|shown| &shown.fields)
            .all(|field| field.extent() == Extent::Whole);
        let full = entries
            .iter()
            .all(|entry| entry.shown(self.level) == Shown::Full);
        let facts = DisplayFacts {
            presentability: if presentable {
                Presentability::WithoutUi
            } else {
                Presentability::OnWalletUi
            },
            transaction_data: TransactionData::of(self.transactions),
            additions: Choice::of_additions(offer),
            subsets: Choice::of_subsets(offer),
            rows: if whole { Rows::Whole } else { Rows::Clipped },
            host: if full {
                HostDisplay::Full
            } else {
                HostDisplay::Skipped
            },
        };
        match WalletDisplay::of(&facts) {
            WalletDisplay::NotNeeded => DelegationType::Full,
            WalletDisplay::Needed => DelegationType::NoDelegation,
        }
    }
}

/// The fields of what `credential` answers for `answers`: the rows of the claims it discloses,
/// or the proof statement rows of the `zkp_req` option it answers.
fn fields(
    index: OfferIndex,
    answers: &Answers<'_, &RegisteredCredential, NoChoice>,
    credential: &RegisteredCredential,
    answer: &Answer,
) -> Result<Vec<siros_display::Field>, Unshown> {
    match answer {
        Answer::Claims(claims) => credential
            .labels()
            .rows(credential.claims(), claims.pointers())
            .map(|rows| rows.iter().map(siros_display::Field::of_claim).collect())
            .map_err(|error| Unshown::Display(index, error.code())),
        Answer::Proof(choice) => {
            let zkp = answers.zkp().ok_or(Unshown::Inconsistent(index))?;
            let option = zkp
                .option(choice)
                .map_err(|error| Unshown::Display(index, error.code()))?;
            siros_display::proof::rows(zkp.query().query(), option)
                .map_err(|error| Unshown::Display(index, error.code()))
        }
    }
}

impl<'a> HostEntry<'a> {
    /// The host strings of `shown`, under the verifier's purpose `disclaimer`.
    fn of(shown: &Presented<'a>, disclaimer: Option<&str>) -> Self {
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
            cred_id: C8String::from_str_lossy(&shown.pick.credential().to_string()),
            title: C8String::from_str_lossy(card.title().as_str()),
            subtitle: C8String::from_str_lossy(card.issuer().as_str()),
            disclaimer: disclaimer.map(C8String::from_str_lossy),
            data: C8String::from_str_lossy(&shown.pick.to_json().to_string()),
            icon: card.icon().as_bytes(),
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
