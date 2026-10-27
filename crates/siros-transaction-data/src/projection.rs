//! A definition projected to the wallet's language: one entry per localised array, the one the
//! locale function takes (PaSO View, Section 4). The other locales are stripped; everything else
//! stays.

use siros_codec::json::Json;
use siros_dcql::PathComponent;
use siros_display::{Locale, Localized};

use crate::definition::{
    ActionLabel, ClaimDefinition, ClaimDisplay, ClaimIndex, Definition, HintEntry, LabelRole,
    Localizations, Mandatory, OtherUiElement, Prominence, TransactionTitle, UiLabel, ValueType,
    AFFIRMATIVE, DENIAL, SECURITY_HINT, TITLE,
};
use crate::json::{quoted, write};

/// A definition in one language. Only [`Definition::project`] constructs it.
#[derive(Debug, Clone, PartialEq)]
pub struct Projected {
    language: Locale,
    claims: Vec<ProjectedClaim>,
    affirmative: Option<UiLabel<ActionLabel>>,
    denial: Option<UiLabel<ActionLabel>>,
    title: Option<UiLabel<TransactionTitle>>,
    security_hint: Option<HintEntry>,
    others: Vec<(String, UiLabel<OtherUiElement>)>,
    extra: Vec<(String, Json)>,
}

/// A claim in one language: its display entry, when it has a `display` array.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectedClaim {
    definition: ClaimDefinition,
    display: Option<ClaimDisplay>,
}

/// The localised array no entry of which the locale function takes for the wallet's language.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Unmatched {
    /// The `display` array of the claim at this position.
    Claim(ClaimIndex),
    /// The `ui_labels` array of this element PaSO defines.
    UiElement(&'static str),
}

impl Unmatched {
    /// A stable identifier.
    #[must_use]
    pub fn code(&self) -> &'static str {
        "language_unmatched"
    }
}

siros_codec::display_code!(Unmatched);

impl std::error::Error for Unmatched {}

impl Definition {
    /// The definition in `language`: every claim `display` array and every `ui_labels` array of
    /// an element PaSO defines has the entry the locale function takes (PaSO View, Section 4).
    /// An element PaSO does not define keeps its entry when it has one.
    ///
    /// # Errors
    ///
    /// [`Unmatched`]: the first array without an entry for `language`. The credential then
    /// does not support the type in the wallet's language.
    pub fn project(&self, language: &Locale) -> Result<Projected, Unmatched> {
        let claims = self
            .claims()
            .iter()
            .enumerate()
            .map(|(at, claim)| {
                let display = claim
                    .display()
                    .map(|display| {
                        display
                            .lookup(language)
                            .cloned()
                            .ok_or(Unmatched::Claim(ClaimIndex::new(at)))
                    })
                    .transpose()?;
                Ok(ProjectedClaim {
                    definition: claim.clone(),
                    display,
                })
            })
            .collect::<Result<Vec<_>, Unmatched>>()?;
        let ui = self.ui_labels();
        Ok(Projected {
            language: language.clone(),
            claims,
            affirmative: matched(ui.affirmative(), language, AFFIRMATIVE)?,
            denial: matched(ui.denial(), language, DENIAL)?,
            title: matched(ui.title(), language, TITLE)?,
            security_hint: matched(ui.security_hint(), language, SECURITY_HINT)?,
            others: ui
                .others()
                .iter()
                .filter_map(|(name, labels)| {
                    labels.lookup(language).map(|l| (name.clone(), l.clone()))
                })
                .collect(),
            extra: self.extra().to_vec(),
        })
    }
}

/// The entry of `labels`, the element `name`, for `language`; `None` without the element.
fn matched<T: Localized + Clone>(
    labels: Option<&Localizations<T>>,
    language: &Locale,
    name: &'static str,
) -> Result<Option<T>, Unmatched> {
    labels
        .map(|labels| {
            labels
                .lookup(language)
                .cloned()
                .ok_or(Unmatched::UiElement(name))
        })
        .transpose()
}

impl Projected {
    /// The wallet's language the definition is projected to.
    #[must_use]
    pub fn language(&self) -> &Locale {
        &self.language
    }

    /// The claims, in the definition's order.
    #[must_use]
    pub fn claims(&self) -> &[ProjectedClaim] {
        &self.claims
    }

    /// `affirmative_action_label`.
    #[must_use]
    pub fn affirmative(&self) -> Option<&UiLabel<ActionLabel>> {
        self.affirmative.as_ref()
    }

    /// `denial_action_label`.
    #[must_use]
    pub fn denial(&self) -> Option<&UiLabel<ActionLabel>> {
        self.denial.as_ref()
    }

    /// `transaction_title`.
    #[must_use]
    pub fn title(&self) -> Option<&UiLabel<TransactionTitle>> {
        self.title.as_ref()
    }

    /// `security_hint`.
    #[must_use]
    pub fn security_hint(&self) -> Option<&HintEntry> {
        self.security_hint.as_ref()
    }

    /// The JSON text of the definition in the form of PaSO Proof Metadata, Section 3, each
    /// array with its one entry. The text is a function of the definition and the language:
    /// members in a fixed order, claims and elements in the metadata's.
    #[must_use]
    pub fn to_json(&self) -> String {
        let claims: Vec<String> = self.claims.iter().map(ProjectedClaim::to_json).collect();
        let mut labels: Vec<String> = Vec::new();
        push_label(&mut labels, AFFIRMATIVE, self.affirmative.as_ref());
        push_label(&mut labels, DENIAL, self.denial.as_ref());
        push_label(&mut labels, TITLE, self.title.as_ref());
        if let Some(hint) = &self.security_hint {
            labels.push(element(
                SECURITY_HINT,
                &entry_json(hint.locale(), &[("value", quoted(hint.value().as_str()))]),
            ));
        }
        for (name, label) in &self.others {
            labels.push(element(name, &ui_label_json(label)));
        }
        let mut members = vec![
            format!("\"claims\":[{}]", claims.join(",")),
            format!("\"ui_labels\":{{{}}}", labels.join(",")),
        ];
        members.extend(
            self.extra
                .iter()
                .map(|(name, value)| format!("{}:{}", quoted(name), write(value))),
        );
        format!("{{{}}}", members.join(","))
    }
}

impl ProjectedClaim {
    /// The claim's definition.
    #[must_use]
    pub fn definition(&self) -> &ClaimDefinition {
        &self.definition
    }

    /// The display entry the locale function took; `None` for an internal claim.
    #[must_use]
    pub fn display(&self) -> Option<&ClaimDisplay> {
        self.display.as_ref()
    }

    fn to_json(&self) -> String {
        let definition = &self.definition;
        let path: Vec<String> = definition
            .path()
            .components()
            .iter()
            .map(|component| match component {
                PathComponent::Key(key) => quoted(key),
                PathComponent::Index(index) => index.to_string(),
                PathComponent::Null => "null".to_owned(),
            })
            .collect();
        let mut members = vec![
            format!("\"path\":[{}]", path.join(",")),
            format!(
                "\"mandatory\":{}",
                definition.mandatory() == Mandatory::Required
            ),
        ];
        if let Some(value_type) = definition.value_type() {
            members.push(format!(
                "\"value_type\":{}",
                quoted(&ValueType::name(value_type))
            ));
        }
        if let Some(display) = &self.display {
            let mut parts = vec![("name", quoted(display.name().as_str()))];
            if let Some(format) = display.format().name() {
                parts.push(("display_type", quoted(format)));
            }
            if let Some(description) = display.description() {
                parts.push(("description", quoted(description.as_str())));
            }
            members.push(format!(
                "\"display\":[{}]",
                entry_json(display.locale(), &parts)
            ));
        }
        if let Some(prominence) = definition.prominence() {
            members.push(format!(
                "\"visualisation\":{}",
                Prominence::level(prominence)
            ));
        }
        format!("{{{}}}", members.join(","))
    }
}

/// Adds the element `name` of the one entry `label`, when present.
fn push_label<R: LabelRole>(labels: &mut Vec<String>, name: &str, label: Option<&UiLabel<R>>) {
    if let Some(label) = label {
        labels.push(element(name, &ui_label_json(label)));
    }
}

/// The member `name` of `ui_labels`: an array of the one entry `entry`.
fn element(name: &str, entry: &str) -> String {
    format!("{}:[{entry}]", quoted(name))
}

fn ui_label_json<R: LabelRole>(label: &UiLabel<R>) -> String {
    let mut parts = vec![("value", quoted(label.value().as_str()))];
    if let Some(format) = label.format().name() {
        parts.push(("value_type", quoted(format)));
    }
    entry_json(label.locale(), &parts)
}

/// The JSON object of an entry in `locale`, with the members `parts` after `locale`.
fn entry_json(locale: Option<&Locale>, parts: &[(&str, String)]) -> String {
    let members: Vec<String> = locale
        .map(|locale| format!("\"locale\":{}", quoted(locale.as_str())))
        .into_iter()
        .chain(
            parts
                .iter()
                .map(|(name, value)| format!("\"{name}\":{value}")),
        )
        .collect();
    format!("{{{}}}", members.join(","))
}
