//! The writer of the registration layout (`docs/registration.md`).

use rustc_hash::FxHashMap;
use siros_codec::cbor::Value as Cbor;
use siros_display::DescribedLabel;
use siros_presentation::{KeyHolding, Presentability};
use siros_transaction_data::{Projected, ServedTypes};
use siros_trust::IssuerFacts;

use crate::error::Member;
use crate::layout::{format_code, SectionKind, MAGIC, SECTIONS_START};
use crate::registration::{
    Diagnostics, Facts, Icon, Projection, RegisteredCredential, RegisteredType, Version,
};
use crate::wire::write::{self as wire, map};
use crate::wire::{verifier_id_form_name, WireSpan};
use crate::write::WriteError;

/// The bytes of `projection`: the header of [`Version::CURRENT`], the directory, and the
/// sections in its order. The facts come first; the index lists each credential type once,
/// sorted by format code and name; the records of a type follow one another in the wallet's
/// order; each distinct definition and icon is stored once, in the order the facts and the
/// records first name it. Equal projections give equal bytes.
///
/// # Errors
///
/// [`WriteError::TooLarge`] for a section that ends past 4 GiB, or past the longest buffer of
/// the platform.
pub fn encode(projection: &Projection) -> Result<Vec<u8>, WriteError> {
    let mut icons = Pool::default();
    let mut definitions = Pool::default();
    let facts = facts(&projection.facts, &mut icons).encode();
    let records = projection
        .credentials
        .iter()
        .enumerate()
        .map(|(position, credential)| Record {
            credential_type: &credential.credential_type,
            bytes: record(position, credential, &mut icons, &mut definitions).encode(),
        })
        .collect();
    let index = Index::of(records)?;
    lay_out([
        facts,
        index.entries,
        index.names,
        index.records,
        definitions.bytes,
        icons.bytes,
    ])
}

/// A credential's record and its type.
struct Record<'p> {
    credential_type: &'p RegisteredType,
    bytes: Vec<u8>,
}

/// The index, names and records sections.
#[derive(Default)]
struct Index {
    entries: Vec<u8>,
    names: Vec<u8>,
    records: Vec<u8>,
}

/// The bytes of a section that holds each distinct part once, in the order of first use, and
/// where each part lies.
#[derive(Default)]
struct Pool {
    bytes: Vec<u8>,
    placed: FxHashMap<Vec<u8>, WireSpan>,
}

impl Pool {
    /// The span of `part`, added at the end when the section lacks it.
    fn place(&mut self, part: &[u8]) -> WireSpan {
        let bytes = &mut self.bytes;
        *self.placed.entry(part.to_vec()).or_insert_with(|| {
            let span = WireSpan {
                offset: bytes.len() as u64,
                length: part.len() as u64,
            };
            bytes.extend_from_slice(part);
            span
        })
    }
}

impl Index {
    /// The sections of `records`: one entry per type in the index's order, each type's records
    /// together in the wallet's order.
    fn of(mut records: Vec<Record<'_>>) -> Result<Self, WriteError> {
        // A stable sort: the records of a type keep the wallet's order.
        records.sort_by(|a, b| a.credential_type.cmp(b.credential_type));
        let mut groups: Vec<Record<'_>> = Vec::new();
        for record in records {
            match groups.last_mut() {
                Some(group) if group.credential_type == record.credential_type => {
                    group.bytes.extend(record.bytes);
                }
                _ => groups.push(record),
            }
        }
        let mut index = Self::default();
        for group in groups {
            index.add(&group)?;
        }
        Ok(index)
    }

    /// Adds the entry of `group`, its type's name and its records.
    fn add(&mut self, group: &Record<'_>) -> Result<(), WriteError> {
        let name = group.credential_type.as_str().as_bytes();
        let words = [
            Ok(format_code(group.credential_type.format())),
            word(self.names.len(), SectionKind::Names),
            word(name.len(), SectionKind::Names),
            word(self.records.len(), SectionKind::Records),
            word(group.bytes.len(), SectionKind::Records),
        ];
        for value in words {
            self.entries.extend(value?.to_le_bytes());
        }
        self.names.extend_from_slice(name);
        self.records.extend_from_slice(&group.bytes);
        Ok(())
    }
}

/// `value` as a word of the layout.
///
/// # Errors
///
/// [`WriteError::TooLarge`] of `kind` for a value past a u32.
fn word(value: usize, kind: SectionKind) -> Result<u32, WriteError> {
    u32::try_from(value).map_err(|_| WriteError::TooLarge(kind))
}

/// The blob of `sections`, in the directory's order: the header, the directory, then each
/// section where the one before it ends.
fn lay_out(sections: [Vec<u8>; 6]) -> Result<Vec<u8>, WriteError> {
    let mut directory = Vec::new();
    let mut end = SECTIONS_START;
    for (kind, section) in SectionKind::ALL.iter().zip(&sections) {
        let start = end;
        let length = word(section.len(), *kind)?;
        end = start
            .checked_add(length)
            .filter(|end| isize::try_from(*end).is_ok())
            .ok_or(WriteError::TooLarge(*kind))?;
        for value in [kind.code(), start, length] {
            directory.extend(value.to_le_bytes());
        }
    }
    // `end` is at most isize::MAX, the most a buffer holds, and a u32, which the usize of every
    // target the crate builds for holds. Below that, the allocation aborts when the platform
    // has no memory for the blob.
    let mut blob = Vec::with_capacity(end as usize);
    blob.extend_from_slice(MAGIC.as_flattened());
    blob.extend(Version::CURRENT.number().to_le_bytes());
    blob.extend(directory);
    for section in sections {
        blob.extend(section);
    }
    Ok(blob)
}

/// The facts map: the time, the language, the diagnostics, the systems, the `verifier_id` form,
/// and the span of the wallet's icon, placed in `icons`.
fn facts(facts: &Facts<Icon>, icons: &mut Pool) -> Cbor {
    map([
        (
            Member::RegisteredAt,
            Cbor::Tag(0, Box::new(Cbor::Text(facts.registered_at.to_string()))),
        ),
        (Member::Language, Cbor::text(facts.language.as_str())),
        (
            Member::Diagnostics,
            Cbor::Bool(facts.diagnostics == Diagnostics::Shown),
        ),
        (
            Member::Systems,
            Cbor::Array(
                facts
                    .systems
                    .iter()
                    .map(|system| Cbor::text(system.id().as_str()))
                    .collect(),
            ),
        ),
        (
            Member::VerifierId,
            Cbor::text(verifier_id_form_name(facts.verifier_id)),
        ),
        (
            Member::DefaultIcon,
            wire::span(icons.place(facts.default_icon.as_bytes())),
        ),
    ])
}

/// The record of `credential` at `position` in the wallet's order, its icon placed in `icons`
/// and its definitions in `definitions`.
fn record(
    position: usize,
    credential: &RegisteredCredential<Projected, Icon>,
    icons: &mut Pool,
    definitions: &mut Pool,
) -> Cbor {
    let card = &credential.card;
    let labels = &credential.labels;
    map([
        (Member::Position, Cbor::Unsigned(position as u64)),
        (Member::Entry, wire::entry(credential.entry)),
        (Member::Key, Cbor::Bool(credential.key == KeyHolding::Held)),
        (Member::Claims, credential.claims.to_cbor()),
        (
            Member::Card,
            map([
                (Member::Title, Cbor::text(card.title.as_str())),
                (Member::Issuer, Cbor::text(card.issuer.as_str())),
                (Member::Icon, wire::span(icons.place(card.icon.as_bytes()))),
            ]),
        ),
        (
            Member::Labels,
            map([
                (Member::TypeLabels, described(labels.types())),
                (Member::IssuerLabels, described(labels.issuer())),
            ]),
        ),
        (
            Member::Background,
            Cbor::Bool(credential.presentability == Presentability::WithoutUi),
        ),
        (Member::Trust, trust(&credential.issuer)),
        (
            Member::Transactions,
            transactions(&credential.transactions, definitions),
        ),
    ])
}

/// The descriptions `descriptions`, each `[path, label]`, or `[path]` without a label in the
/// wallet's language.
fn described(descriptions: &[DescribedLabel]) -> Cbor {
    Cbor::Array(
        descriptions
            .iter()
            .map(|description| {
                let path = wire::path(description.path());
                let label = description.label().map(|label| Cbor::text(label.as_str()));
                Cbor::Array(std::iter::once(path).chain(label).collect())
            })
            .collect(),
    )
}

/// The issuer facts `facts` (TR5).
fn trust(facts: &IssuerFacts) -> Cbor {
    map([
        (
            Member::KeyIdentifiers,
            Cbor::Array(
                facts
                    .key_identifiers()
                    .iter()
                    .map(|key| Cbor::Bytes(key.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
        (
            Member::Admitting,
            Cbor::Array(facts.admitting().iter().map(wire::authority).collect()),
        ),
    ])
}

/// What `served` gives each type: the span of the projected definition, placed in
/// `definitions`, or why there is none.
fn transactions(served: &ServedTypes<Projected>, definitions: &mut Pool) -> Cbor {
    let types = served
        .types()
        .iter()
        .map(|(type_id, served)| {
            let served = match served {
                Ok(definition) => wire::span(definitions.place(definition.to_json().as_bytes())),
                Err(unserved) => wire::unserved(*unserved),
            };
            Cbor::Array(vec![Cbor::text(type_id.as_str()), served])
        })
        .collect();
    map([
        (Member::ServedTypes, Cbor::Array(types)),
        (Member::Otherwise, wire::unserved(served.otherwise())),
    ])
}
