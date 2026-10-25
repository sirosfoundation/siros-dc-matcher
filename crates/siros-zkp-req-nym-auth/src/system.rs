//! The nym_auth systems of the rulebook and the requests each supports (system rulebooks,
//! Sections 1 to 3).
//!
//! `urn:mms:bbs-cd:nym_auth:v1` is not listed: no Wallet proves it yet.

use std::fmt;

use siros_zkp_req::{CredentialType, PairRefusal};

use crate::age::Bounds;
use crate::catalogue::{Config, Form, Function, Item, Prf, MDOC_DOCTYPE};
use crate::date::Date;

/// A nym_auth system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NymAuthSystem {
    /// `urn:circuits:longfellow:nym_auth:v1` on `longfellow-libzk-v1`.
    LongfellowV1,
    /// `urn:circuits:vega:nym_auth:v1` on `vega-v1`.
    VegaV1,
}

/// Why a system answers `unsupported` for an option (system rulebooks, Section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unsupported {
    /// The option has no `pseudonym` item.
    NoPseudonym,
    /// `pseudonym.config` is another configuration than `known-offender-matching-ssc`.
    Config,
    /// `pseudonym.prf` is another PRF than `sha-256`.
    Prf,
    /// E or C lies outside the dates the system encodes.
    AgeBounds,
}

impl Unsupported {
    /// A stable identifier.
    pub fn code(self) -> &'static str {
        match self {
            Self::NoPseudonym => "no_pseudonym",
            Self::Config => "config",
            Self::Prf => "prf",
            Self::AgeBounds => "age_bounds",
        }
    }
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// The stable identifier of a pair refusal (`zkp_req`, Section 1.3) for a nym_auth system.
pub fn pair_code(refusal: &PairRefusal<Unsupported>) -> &'static str {
    match refusal {
        PairRefusal::SystemNotListed => "system_not_listed",
        PairRefusal::NoListedBackend => "no_listed_backend",
        PairRefusal::CredentialType => "credential_type",
        PairRefusal::Unsupported(u) => u.code(),
    }
}

impl NymAuthSystem {
    /// Every system of this crate.
    pub const ALL: [Self; 2] = [Self::LongfellowV1, Self::VegaV1];

    /// The system identifier.
    pub fn id(self) -> &'static str {
        match self {
            Self::LongfellowV1 => "urn:circuits:longfellow:nym_auth:v1",
            Self::VegaV1 => "urn:circuits:vega:nym_auth:v1",
        }
    }

    /// The system with identifier `id`.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.id() == id)
    }

    /// The proof backends the system runs on (Section 1).
    pub fn backends(self) -> &'static [&'static str] {
        match self {
            Self::LongfellowV1 => &["longfellow-libzk-v1"],
            Self::VegaV1 => &["vega-v1"],
        }
    }

    /// The attestation form it proves over.
    pub fn form(self) -> Form {
        Form::Mdoc
    }

    /// The dates E and C may take (Section 2): 0000-01-01 to 9999-12-31 for both systems.
    pub fn bound_window(self) -> (Date, Date) {
        match self {
            Self::LongfellowV1 | Self::VegaV1 => (Date::FIRST, Date::LAST),
        }
    }

    /// The exact length of `zk_proof` the system rulebook states, if it states one.
    pub fn zk_proof_len(self) -> Option<usize> {
        match self {
            Self::LongfellowV1 => None,
            Self::VegaV1 => Some(96_079),
        }
    }

    /// Whether the system supports an option: its items, and E and C at the proof date
    /// (Section 2).
    ///
    /// # Errors
    ///
    /// [`Unsupported`]: the first rule of Section 2 the option breaks.
    pub fn supports<'a>(
        self,
        items: impl IntoIterator<Item = &'a Item>,
        bounds: &Bounds,
    ) -> Result<(), Unsupported> {
        let mut pseudonym = false;
        for item in items {
            if let Function::Pseudonym(p) = &item.function {
                if p.config != Config::KnownOffenderMatchingSsc {
                    return Err(Unsupported::Config);
                }
                if p.prf != Prf::Sha256 {
                    return Err(Unsupported::Prf);
                }
                pseudonym = true;
            }
        }
        if !pseudonym {
            return Err(Unsupported::NoPseudonym);
        }
        let (min, max) = self.bound_window();
        if !bounds.within(min, max) {
            return Err(Unsupported::AgeBounds);
        }
        Ok(())
    }
}

impl siros_zkp_req::System for NymAuthSystem {
    fn id(&self) -> &str {
        NymAuthSystem::id(*self)
    }

    fn runs_on(&self, backend: &str) -> bool {
        self.backends().contains(&backend)
    }

    fn proves_over(&self, credential_type: &CredentialType) -> bool {
        matches!(credential_type, CredentialType::MsoMdoc { doctype } if doctype == MDOC_DOCTYPE)
    }
}
