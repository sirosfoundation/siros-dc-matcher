//! What the consent screen shows for one transaction: the generic rendering of PaSO View, Section
//! 2, for every type and every source.

use siros_oid4vp::RequestSignature;

use crate::definition::{LabelFormat, LabelText, Prominence, SecurityHint};
use crate::image::VerifiedImage;
use crate::payload::{Location, Scalar};
use crate::sources::{Rulebook, SourceKind};
use crate::type_id::TypeId;

/// The display of one transaction data entry: its UI elements and a row per displayed claim
/// instance, in the order of the definition's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionView {
    pub(crate) type_id: TypeId,
    pub(crate) source: SourceKind,
    pub(crate) rulebook: Rulebook,
    pub(crate) title: Option<ShownLabel>,
    pub(crate) affirmative: Option<ShownLabel>,
    pub(crate) denial: Option<ShownLabel>,
    pub(crate) security_hint: Option<LabelText<SecurityHint>>,
    pub(crate) rows: Vec<Row>,
    pub(crate) signature: RequestSignature,
}

/// A label as shown: its text, interpolated when it was a template, and how it is formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownLabel {
    pub(crate) text: String,
    pub(crate) format: LabelFormat,
}

/// A displayed claim instance: its location in the payload, its label, its value, and the
/// prominence TS12 type metadata gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub(crate) location: Location,
    pub(crate) label: ShownLabel,
    pub(crate) value: RowValue,
    pub(crate) prominence: Option<Prominence>,
}

/// The value of a row, typed for the UI to format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowValue {
    /// `label_only`: the label is shown alone.
    LabelOnly,
    /// A value formatted by its type.
    Value(Scalar),
    /// An image, verified.
    Image(VerifiedImage),
}

/// Whether the UI warns that the request arrived unsigned, and requires explicit confirmation
/// before it continues (EC TS12 v1.0.1, Section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsignedWarning {
    /// The request is unsigned and the type's rulebook is TS12's: warn and confirm.
    Required,
    /// The request arrived signed, or the rulebook is no TS12 one.
    NotNeeded,
}

impl TransactionView {
    /// The `type` value.
    #[must_use]
    pub fn type_id(&self) -> &TypeId {
        &self.type_id
    }

    /// The source of the definition the view renders.
    #[must_use]
    pub fn source(&self) -> SourceKind {
        self.source
    }

    /// The rulebook of the payload.
    #[must_use]
    pub fn rulebook(&self) -> Rulebook {
        self.rulebook
    }

    /// `transaction_title`. `None`: the wallet may title the screen itself.
    #[must_use]
    pub fn transaction_title(&self) -> Option<&ShownLabel> {
        self.title.as_ref()
    }

    /// `affirmative_action_label`. `None`: the wallet labels the control that confirms.
    #[must_use]
    pub fn affirmative_action_label(&self) -> Option<&ShownLabel> {
        self.affirmative.as_ref()
    }

    /// `denial_action_label`. `None`: the wallet labels the control that cancels.
    #[must_use]
    pub fn denial_action_label(&self) -> Option<&ShownLabel> {
        self.denial.as_ref()
    }

    /// `security_hint`, shown exactly as given (PaSO View, Section 2).
    #[must_use]
    pub fn security_hint(&self) -> Option<&LabelText<SecurityHint>> {
        self.security_hint.as_ref()
    }

    /// The rows, in the order of the definition's claims, wildcards expanded (PaSO View,
    /// Section 2).
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    /// Whether the UI warns that the request arrived unsigned (EC TS12 v1.0.1, Section 3.1).
    #[must_use]
    pub fn unsigned_warning(&self) -> UnsignedWarning {
        match (self.signature, self.rulebook) {
            (RequestSignature::Unsigned, Rulebook::Ts12(_)) => UnsignedWarning::Required,
            (RequestSignature::Signed, _) | (RequestSignature::Unsigned, Rulebook::Generic) => {
                UnsignedWarning::NotNeeded
            }
        }
    }
}

impl ShownLabel {
    /// The text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// How the text is formatted: plain or `mini_markdown`.
    #[must_use]
    pub fn format(&self) -> LabelFormat {
        self.format
    }
}

impl Row {
    /// The claim instance's location in the payload.
    #[must_use]
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// The label.
    #[must_use]
    pub fn label(&self) -> &ShownLabel {
        &self.label
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &RowValue {
        &self.value
    }

    /// The prominence TS12 type metadata gives the row (EC TS12 v1.0.1, Section 3.3.1).
    #[must_use]
    pub fn prominence(&self) -> Option<Prominence> {
        self.prominence
    }
}
