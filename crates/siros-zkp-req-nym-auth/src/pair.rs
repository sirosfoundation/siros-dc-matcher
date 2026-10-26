//! The options of a nym_auth query, and the usable pair of a system and a proof backend for an
//! option at a proof date (`zkp_req`, Section 1.3).

use siros_codec::date::Date;
use siros_zkp_req::{usable_backend, PairRefusal, QueryOption, ZkpFormats};

use crate::age::Bounds;
use crate::catalogue::{Function, NymAuthQuery, Pseudonym};
#[cfg(feature = "credential")]
use crate::outcome::{ItemCode, ZkpError};
use crate::system::{NymAuthSystem, Unsupported};

/// An option of a nym_auth query.
#[derive(Debug, Clone, Copy)]
pub struct NymAuthOption<'q> {
    query: &'q NymAuthQuery,
    option: &'q QueryOption,
}

impl NymAuthQuery {
    /// The options, in the Verifier's order of preference.
    pub fn options(&self) -> impl Iterator<Item = NymAuthOption<'_>> {
        self.query()
            .options
            .iter()
            .map(move |option| NymAuthOption {
                query: self,
                option,
            })
    }
}

impl<'q> NymAuthOption<'q> {
    /// The query.
    pub fn query(&self) -> &'q NymAuthQuery {
        self.query
    }

    /// The option as `zkp_req` reads it.
    pub fn option(&self) -> &'q QueryOption {
        self.option
    }

    /// The usable pair of `system` for this option at the proof date `d`. The proof backend is
    /// the first of the Verifier's `proof_backend_values` the system runs on.
    ///
    /// # Errors
    ///
    /// [`PairRefusal`]: the first rule of Section 1.3 that fails.
    pub fn pair(
        self,
        formats: &ZkpFormats,
        system: NymAuthSystem,
        d: Date,
    ) -> Result<UsablePair<'q>, PairRefusal<Unsupported>> {
        let bounds = self.query.option_bounds(self.option, d);
        let items = self.query.option_items(self.option).map(|(_, item)| item);
        let backend = usable_backend(formats, &self.query.query().credential_type, &system, |s| {
            s.supports(items, &bounds)
        })?;
        // Every system supports only options with a `pseudonym`.
        let pseudonym = self
            .query
            .option_items(self.option)
            .find_map(|(index, item)| match &item.function {
                Function::Pseudonym(pseudonym) => Some((index, pseudonym)),
                Function::AgeCheck(_) => None,
            })
            .ok_or(PairRefusal::Unsupported(Unsupported::NoPseudonym))?;
        Ok(UsablePair {
            option: self,
            system,
            backend: backend.to_owned(),
            date: d,
            bounds,
            pseudonym,
        })
    }
}

/// A system and a proof backend that form a usable pair for an option at a proof date. Its
/// bounds are those of the option's `age_check` at that date, and the system encodes them. The
/// option has a `pseudonym`.
#[derive(Debug, Clone)]
pub struct UsablePair<'q> {
    option: NymAuthOption<'q>,
    system: NymAuthSystem,
    backend: String,
    date: Date,
    bounds: Bounds,
    pseudonym: (usize, &'q Pseudonym),
}

impl<'q> UsablePair<'q> {
    /// The option.
    pub fn option(&self) -> NymAuthOption<'q> {
        self.option
    }

    /// The system.
    pub fn system(&self) -> NymAuthSystem {
        self.system
    }

    /// The proof backend.
    pub fn backend(&self) -> &str {
        &self.backend
    }

    /// D, the proof date.
    pub fn date(&self) -> Date {
        self.date
    }

    /// E and C of the option at the proof date.
    pub fn bounds(&self) -> &Bounds {
        &self.bounds
    }

    /// The option's `pseudonym` item and its `_req` index.
    pub fn pseudonym(&self) -> (usize, &'q Pseudonym) {
        self.pseudonym
    }
}

/// The assertions of `option` that fail for `birth_date` under `bounds`: its `age_check`.
#[cfg(feature = "credential")]
pub(crate) fn failed_assertions(
    query: &NymAuthQuery,
    option: &QueryOption,
    bounds: &Bounds,
    birth_date: Date,
) -> Vec<ZkpError> {
    query
        .option_items(option)
        .filter_map(|(index, item)| match item.function {
            Function::AgeCheck(_) if !bounds.holds(birth_date) => Some(ZkpError::Item {
                option: option.req_set,
                item: index,
                code: ItemCode::AgeOutOfRange,
            }),
            _ => None,
        })
        .collect()
}
