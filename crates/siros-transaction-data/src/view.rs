//! What the consent screen shows for one transaction (EC TS12 v1.0.1, Section 3.3).

use siros_codec::date::Date;
use siros_display::DisplayText;

use crate::kind::SupportedType;
use crate::ts12::ImageUrl;

/// The display of one transaction data entry: the UI elements of its type (Section 3.3.3) and
/// a row per leaf parameter of its payload (Sections 3.3.1 and 3.3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionView {
    transaction_type: SupportedType,
    labels: Labels,
    rows: Vec<Row>,
}

/// The UI elements of a transaction (Section 3.3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Labels {
    pub(crate) affirmative: DisplayText,
    pub(crate) denial: Option<DisplayText>,
    pub(crate) title: Option<DisplayText>,
    pub(crate) security_hint: Option<DisplayText>,
}

impl TransactionView {
    pub(crate) fn new(transaction_type: SupportedType, labels: Labels, rows: Vec<Row>) -> Self {
        Self {
            transaction_type,
            labels,
            rows,
        }
    }

    /// The `type` value.
    #[must_use]
    pub fn transaction_type(&self) -> SupportedType {
        self.transaction_type
    }

    /// `affirmative_action_label`: the label of the control that confirms.
    #[must_use]
    pub fn affirmative_action_label(&self) -> &DisplayText {
        &self.labels.affirmative
    }

    /// `denial_action_label`. `None`: the wallet labels the control that cancels.
    #[must_use]
    pub fn denial_action_label(&self) -> Option<&DisplayText> {
        self.labels.denial.as_ref()
    }

    /// `transaction_title`. `None`: the wallet may title the screen itself.
    #[must_use]
    pub fn transaction_title(&self) -> Option<&DisplayText> {
        self.labels.title.as_ref()
    }

    /// `security_hint`. `None`: no hint is shown.
    #[must_use]
    pub fn security_hint(&self) -> Option<&DisplayText> {
        self.labels.security_hint.as_ref()
    }

    /// The rows, by level, in the order of the type's schema within a level.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.rows
    }
}

/// A leaf parameter of the payload with its localised name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    label: DisplayText,
    value: RowValue,
    level: Level,
}

impl Row {
    pub(crate) fn new(label: DisplayText, value: RowValue, level: Level) -> Self {
        Self {
            label,
            value,
            level,
        }
    }

    /// The localised name of the parameter.
    #[must_use]
    pub fn label(&self) -> &DisplayText {
        &self.label
    }

    /// The value.
    #[must_use]
    pub fn value(&self) -> &RowValue {
        &self.value
    }

    /// How prominently the row is shown.
    #[must_use]
    pub fn level(&self) -> Level {
        self.level
    }
}

/// The value of a row, typed for the UI to format for its locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowValue {
    /// A string. An array or `null` in a member the schema leaves open shows as its compact
    /// JSON text.
    Text(DisplayText),
    /// A number, as the verifier wrote it in JSON.
    Number(DisplayText),
    /// A boolean.
    Boolean(bool),
    /// A calendar date.
    Date(Date),
    /// The URL of an image, for the UI to show.
    Image(ImageUrl),
    /// A recurrence frequency, which the wallet names in the user's language (Section 4.3.1).
    Frequency(Frequency),
}

/// A visualisation level of Section 3.3.1, most prominent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// `1`: shown prominently on the main confirmation screen.
    Prominent,
    /// `2`: shown on the main confirmation screen.
    Main,
    /// `3`, the default: shown, possibly on a supplementary screen.
    Supplementary,
    /// `4`: may be omitted.
    Omittable,
}

impl Level {
    /// The level of the `visualisation` value `value`.
    pub(crate) fn of(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Prominent),
            2 => Some(Self::Main),
            3 => Some(Self::Supplementary),
            4 => Some(Self::Omittable),
            _ => None,
        }
    }
}

/// A recurrence frequency: an ISO 20022 code of EC TS12 v1.0.1, Section 4.3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Frequency {
    /// `INDA`: several times a day.
    Intraday,
    /// `DAIL`: daily.
    Daily,
    /// `WEEK`: weekly.
    Weekly,
    /// `TOWK`: every two weeks.
    EveryTwoWeeks,
    /// `TWMN`: twice a month.
    TwiceAMonth,
    /// `MNTH`: monthly.
    Monthly,
    /// `TOMN`: every two months.
    EveryTwoMonths,
    /// `QUTR`: quarterly.
    Quarterly,
    /// `FOMN`: every four months.
    EveryFourMonths,
    /// `SEMI`: twice a year.
    TwiceAYear,
    /// `YEAR`: yearly.
    Yearly,
    /// `TYEA`: every two years.
    EveryTwoYears,
}

impl Frequency {
    const ALL: [Self; 12] = [
        Self::Intraday,
        Self::Daily,
        Self::Weekly,
        Self::EveryTwoWeeks,
        Self::TwiceAMonth,
        Self::Monthly,
        Self::EveryTwoMonths,
        Self::Quarterly,
        Self::EveryFourMonths,
        Self::TwiceAYear,
        Self::Yearly,
        Self::EveryTwoYears,
    ];

    /// The ISO 20022 code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Intraday => "INDA",
            Self::Daily => "DAIL",
            Self::Weekly => "WEEK",
            Self::EveryTwoWeeks => "TOWK",
            Self::TwiceAMonth => "TWMN",
            Self::Monthly => "MNTH",
            Self::EveryTwoMonths => "TOMN",
            Self::Quarterly => "QUTR",
            Self::EveryFourMonths => "FOMN",
            Self::TwiceAYear => "SEMI",
            Self::Yearly => "YEAR",
            Self::EveryTwoYears => "TYEA",
        }
    }

    /// The frequency of the code `code`.
    pub(crate) fn named(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.code() == code)
    }
}
