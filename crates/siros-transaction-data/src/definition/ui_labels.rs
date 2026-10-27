//! The UI labels of a definition (PaSO Proof Metadata, Section 3.2): localised strings for the
//! consent UI, each element with its length limit (Section 3.3).

use siros_codec::json::Json;
use siros_display::{Locale, Localized};

use super::claim::{label, label_format};
use super::error::{DefinitionError, DefinitionMember, EntryFault, LabelsFault};
use super::localized::{self, Localizations};
use super::text::{
    ActionLabel, LabelRole, LabelText, OtherUiElement, SecurityHint, TransactionTitle,
};
use super::value_type::LabelFormat;
use crate::json::Fields;

/// A `ui_labels` entry of a label of role `R`: its locale, its `value`, and how the value is
/// formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiLabel<R> {
    pub(crate) locale: Option<Locale>,
    pub(crate) value: LabelText<R>,
    pub(crate) format: LabelFormat,
}

impl<R> Localized for UiLabel<R> {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}

impl<R: LabelRole> UiLabel<R> {
    /// The entry of `fields`: `locale`, `value`, and `value_type` (Sections 3.2 and 3.3).
    fn parse(mut fields: Fields) -> Result<Self, EntryFault> {
        let locale = localized::locale(&mut fields)?;
        let value = localized::required_text(&mut fields, DefinitionMember::Value)?;
        let format = label_format(&mut fields, "value_type")?;
        Ok(Self {
            locale,
            value: label(&value, format, DefinitionMember::Value)?,
            format,
        })
    }

    /// The `value`.
    #[must_use]
    pub fn value(&self) -> &LabelText<R> {
        &self.value
    }

    /// How the value is formatted.
    #[must_use]
    pub fn format(&self) -> LabelFormat {
        self.format
    }
}

/// A `security_hint` entry: its locale and its plain-text `value` (Sections 3.2 and 3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HintEntry {
    pub(crate) locale: Option<Locale>,
    pub(crate) value: LabelText<SecurityHint>,
}

impl Localized for HintEntry {
    fn locale(&self) -> Option<&Locale> {
        self.locale.as_ref()
    }
}

impl HintEntry {
    /// The entry of `fields`: `locale` and `value`, without `value_type`.
    fn parse(mut fields: Fields) -> Result<Self, EntryFault> {
        let locale = localized::locale(&mut fields)?;
        let value = localized::required_text(&mut fields, DefinitionMember::Value)?;
        if fields.take("value_type").is_some() {
            return Err(EntryFault::HintFormat);
        }
        Ok(Self {
            locale,
            value: label(&value, LabelFormat::Plain, DefinitionMember::Value)?,
        })
    }

    /// The `value`, shown exactly as given.
    #[must_use]
    pub fn value(&self) -> &LabelText<SecurityHint> {
        &self.value
    }
}

/// The `ui_labels` object: the four elements PaSO defines, and the others, each a localised
/// array.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UiLabels {
    pub(crate) affirmative: Option<Localizations<UiLabel<ActionLabel>>>,
    pub(crate) denial: Option<Localizations<UiLabel<ActionLabel>>>,
    pub(crate) title: Option<Localizations<UiLabel<TransactionTitle>>>,
    pub(crate) security_hint: Option<Localizations<HintEntry>>,
    pub(crate) others: Vec<(String, Localizations<UiLabel<OtherUiElement>>)>,
}

/// `affirmative_action_label`.
pub(crate) const AFFIRMATIVE: &str = "affirmative_action_label";
/// `denial_action_label`.
pub(crate) const DENIAL: &str = "denial_action_label";
/// `transaction_title`.
pub(crate) const TITLE: &str = "transaction_title";
/// `security_hint`.
pub(crate) const SECURITY_HINT: &str = "security_hint";

impl UiLabels {
    /// The labels of the `ui_labels` object `value` (Section 3.2). An element another
    /// specification defines has at most 100 extended grapheme clusters (Section 3.3).
    pub(crate) fn parse(value: Json) -> Result<Self, DefinitionError> {
        let Json::Object(members) = value else {
            return Err(DefinitionError::Member(
                DefinitionMember::UiLabels,
                siros_codec::member::MemberFault::WrongType,
            ));
        };
        let mut labels = Self::default();
        for (name, value) in members {
            let fault = |fault: LabelsFault| DefinitionError::UiElement(name.clone(), fault);
            match name.as_str() {
                AFFIRMATIVE => labels.affirmative = Some(array(value).map_err(fault)?),
                DENIAL => labels.denial = Some(array(value).map_err(fault)?),
                TITLE => labels.title = Some(array(value).map_err(fault)?),
                SECURITY_HINT => {
                    labels.security_hint =
                        Some(Localizations::parse(value, HintEntry::parse).map_err(fault)?);
                }
                _ => {
                    let other = array(value).map_err(fault)?;
                    labels.others.push((name, other));
                }
            }
        }
        Ok(labels)
    }

    /// `affirmative_action_label`.
    #[must_use]
    pub fn affirmative(&self) -> Option<&Localizations<UiLabel<ActionLabel>>> {
        self.affirmative.as_ref()
    }

    /// `denial_action_label`.
    #[must_use]
    pub fn denial(&self) -> Option<&Localizations<UiLabel<ActionLabel>>> {
        self.denial.as_ref()
    }

    /// `transaction_title`.
    #[must_use]
    pub fn title(&self) -> Option<&Localizations<UiLabel<TransactionTitle>>> {
        self.title.as_ref()
    }

    /// `security_hint`.
    #[must_use]
    pub fn security_hint(&self) -> Option<&Localizations<HintEntry>> {
        self.security_hint.as_ref()
    }

    /// The elements PaSO does not define, by identifier, in the metadata's order.
    #[must_use]
    pub fn others(&self) -> &[(String, Localizations<UiLabel<OtherUiElement>>)] {
        &self.others
    }
}

/// A `ui_labels` array of labels of role `R`.
fn array<R: LabelRole>(value: Json) -> Result<Localizations<UiLabel<R>>, LabelsFault> {
    Localizations::parse(value, UiLabel::parse)
}
