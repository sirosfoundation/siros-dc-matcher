//! What an entry shows of the transaction its credential takes: the rows of the transaction's
//! view as fields, or, for a payment, the payee, the amount and the other rows.

use siros_display::{Field, FieldText};
use siros_transaction_data::{
    Location, LocationStep, Payment, Row, RowValue, Segment, ShownLabel, Taken, TransactionView,
};

/// What an entry shows of the transaction its credential takes.
pub(crate) enum TransactionShown {
    /// The credential takes no entry, or the wallet decides which after selection (K2).
    Nothing,
    /// The transaction's displayed claims, in claims order: the fields after the credential's
    /// claim fields.
    Rows(Vec<Field>),
    /// A payment: the payee, the amount, and the other displayed text.
    Payment(PaymentShown),
}

/// A payment entry's text.
pub(crate) struct PaymentShown {
    /// `payee.name`.
    pub(crate) payee: String,
    /// The amount and the currency's code.
    pub(crate) amount: String,
    /// The transaction's title and its rows other than the payee and the amount, one line each.
    pub(crate) additional_info: Option<String>,
}

impl TransactionShown {
    /// What an entry shows of `taken`: a payment entry when the entry is of a payment rulebook
    /// whose payload names the payee and the amount, else the view's rows.
    pub(crate) fn of(taken: &Taken) -> Self {
        let view = taken.view();
        match taken.payment() {
            Some(payment) => Self::Payment(PaymentShown::of(payment, view)),
            None => Self::Rows(view.rows().iter().map(field).collect()),
        }
    }
}

impl PaymentShown {
    fn of(payment: &Payment, view: &TransactionView) -> Self {
        let lines: Vec<String> = view
            .transaction_title()
            .map(text)
            .into_iter()
            .chain(
                view.rows()
                    .iter()
                    .filter(|row| !paid(row.location()))
                    .map(|row| {
                        let field = field(row);
                        match field.value() {
                            Some(value) => format!("{}: {}", field.name().as_str(), value.as_str()),
                            None => field.name().as_str().to_owned(),
                        }
                    }),
            )
            .collect();
        Self {
            payee: payment.payee().as_str().to_owned(),
            amount: payment.amount().text(),
            additional_info: (!lines.is_empty()).then(|| lines.join("\n")),
        }
    }
}

/// Whether `location` is that of the payee's name, the amount or the currency, which a payment
/// entry shows on its own.
fn paid(location: &Location) -> bool {
    let key = |name: &str| LocationStep::Key(name.to_owned());
    [
        vec![key("payee"), key("name")],
        vec![key("amount")],
        vec![key("currency")],
    ]
    .iter()
    .any(|steps| location.steps() == steps.as_slice())
}

/// The field of a displayed claim: its label, and its value as one line. An image shows
/// clipped.
fn field(row: &Row) -> Field {
    let value = match row.value() {
        RowValue::LabelOnly => None,
        RowValue::Value(scalar) => Some(FieldText::fit(&scalar.text())),
        RowValue::Template(interpolated) => {
            Some(FieldText::fit(&segments(interpolated.segments())))
        }
        RowValue::Image(_) => Some(FieldText::partial("")),
    };
    Field::new(FieldText::fit(&text(row.label())), value)
}

/// The text of `label`, each value as the payload writes it.
fn text(label: &ShownLabel) -> String {
    segments(label.segments())
}

fn segments(segments: &[Segment]) -> String {
    segments
        .iter()
        .map(|segment| match segment {
            Segment::Text(text) => text.clone(),
            Segment::Value(value) => value.text(),
        })
        .collect()
}
