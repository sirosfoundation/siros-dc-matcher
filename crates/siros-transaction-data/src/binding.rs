//! Each entry bound to one credential of the chosen offer (T4), and what the entries bound to a
//! credential add to its presentation (T3; OpenID4VP 1.0, Section 8.4).

use serde_json::Value;
use siros_codec::base64url::{self, Base64Url};
use siros_credential::Credential;
use siros_dcql::QueryId;
use siros_display::Locale;
use siros_oid4vp::ResponseMode;

use crate::amr::Amr;
use crate::entry::Entry;
use crate::error::TransactionDataError;
use crate::hash::{Accepted, AlgClaim, Choice};
use crate::metadata::{Fetched, ScaMetadata, Step};
use crate::view::TransactionView;

/// What an entry binds into the KB-JWT of the credential that authorizes it.
pub(crate) struct Binding<'a> {
    /// The algorithms of its hash in `transaction_data_hashes` (B.3.3.1).
    pub(crate) hashes: &'a Accepted,
    /// The KB-JWT claims its type's specification requires besides the hashes.
    pub(crate) claims: &'static [KbJwtClaim],
}

/// A KB-JWT claim a transaction data type requires.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum KbJwtClaim {
    /// `jti`: fresh randomness (EC TS12 v1.0.1, Section 3.6).
    Jti,
    /// `response_mode`: the request's Response Mode (EC TS12 v1.0.1, Section 3.6).
    ResponseMode,
    /// `amr`: the factors of the signing key (EC TS12 v1.0.1, Section 3.6).
    Amr,
}

/// The order of the required claims in a KB-JWT.
const CLAIM_ORDER: [KbJwtClaim; 3] = [KbJwtClaim::Jti, KbJwtClaim::ResponseMode, KbJwtClaim::Amr];

impl KbJwtClaim {
    /// The claim's name and its value of `inputs`.
    fn of(self, inputs: &KbJwtInputs) -> (&'static str, Value) {
        match self {
            Self::Jti => ("jti", inputs.jti.as_str().into()),
            Self::ResponseMode => ("response_mode", inputs.response_mode.as_str().into()),
            Self::Amr => ("amr", inputs.amr.claim()),
        }
    }
}

/// A credential the chosen offer presents for a Credential Query, with its SCA Attestation
/// metadata.
#[derive(Clone, Copy)]
pub struct Presented<'a> {
    query_id: &'a QueryId,
    metadata: &'a ScaMetadata<'a>,
}

impl<'a> Presented<'a> {
    /// The credential of `metadata`, presented for the Credential Query `query_id`.
    #[must_use]
    pub fn new(query_id: &'a QueryId, metadata: &'a ScaMetadata<'a>) -> Self {
        Self { query_id, metadata }
    }

    /// The Credential Query id.
    #[must_use]
    pub fn query_id(&self) -> &'a QueryId {
        self.query_id
    }

    /// The credential.
    #[must_use]
    pub fn credential(&self) -> &'a Credential {
        self.metadata.credential()
    }
}

/// The entries bound to one presented credential, and the hash algorithm they share.
pub struct MemberBinding<'e, 'a> {
    presented: Presented<'a>,
    entries: Vec<&'e Entry>,
    choice: Choice,
}

/// Binds each of `entries` to the credential `offer` presents for the first of its
/// `credential_ids` that the type authorizes (OpenID4VP 1.0, Section 5.1). When a query has
/// several credentials, the first in `offer` that the type authorizes is taken.
///
/// `offer` holds the credentials of the chosen offer whose type metadata the host fetched. A
/// credential without type metadata authorizes no entry.
///
/// The bindings are those of the credentials with at least one entry, in the order of `offer`.
/// The entries bound to one credential share the first hash algorithm of the first of them that
/// every one accepts (B.3.3.1).
///
/// # Errors
///
/// [`TransactionDataError::CredentialUnavailable`] for an entry no credential of `offer`
/// authorizes, [`TransactionDataError::HashAlgConflict`] for entries bound to one credential
/// without a common algorithm.
pub fn bind<'e, 'a>(
    entries: &'e [Entry],
    offer: &[Presented<'a>],
) -> Result<Vec<MemberBinding<'e, 'a>>, TransactionDataError> {
    let mut placed = entries
        .iter()
        .map(|entry| {
            authorizing(entry, offer)
                .map(|placed| (placed, entry))
                .ok_or(TransactionDataError::CredentialUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    // Stable: the entries of one credential stay in the order of the request.
    placed.sort_by_key(|(placed, _)| placed.position);
    // Each credential with its entries: a group starts with the credential it holds.
    let mut groups: Vec<(Placed<'a>, Vec<&'e Entry>)> = Vec::new();
    for (placed, entry) in placed {
        match groups.last_mut() {
            Some((last, entries)) if last.position == placed.position => entries.push(entry),
            _ => groups.push((placed, vec![entry])),
        }
    }
    groups
        .into_iter()
        .map(|(placed, entries)| {
            let accepted: Vec<&Accepted> = entries.iter().map(|e| e.binding().hashes).collect();
            Ok(MemberBinding {
                presented: placed.presented,
                choice: Choice::of(&accepted)?,
                entries,
            })
        })
        .collect()
}

/// A credential of the offer, and its position there.
#[derive(Clone, Copy)]
struct Placed<'a> {
    position: usize,
    presented: Presented<'a>,
}

/// The credential of `offer` that `entry` binds to: the first that carries it, for the first of
/// its `credential_ids` one does.
fn authorizing<'a>(entry: &Entry, offer: &[Presented<'a>]) -> Option<Placed<'a>> {
    entry.credential_ids().iter().find_map(|id| {
        offer
            .iter()
            .enumerate()
            .find(|(_, presented)| presented.query_id == id && entry.carried_by(presented))
            .map(|(position, presented)| Placed {
                position,
                presented: *presented,
            })
    })
}

impl Entry {
    /// Whether `presented` can carry the entry: it answers a Credential Query the entry's
    /// `credential_ids` name, and its SCA Attestation metadata authorizes the entry's type
    /// (OpenID4VP 1.0, Section 5.1; EC TS12 v1.0.1, Section 4.1).
    #[must_use]
    pub fn carried_by(&self, presented: &Presented<'_>) -> bool {
        self.names(presented.query_id) && self.body().authorizes(presented.metadata)
    }
}

/// `jti`: a fresh, random KB-JWT identifier (RFC 7519, Section 4.1.7; EC TS12 v1.0.1, Section
/// 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jti(Base64Url);

impl Jti {
    /// The identifier of `random`, 128 bits the host's CSPRNG drew for this presentation: their
    /// base64url.
    #[must_use]
    pub fn new(random: [u8; 16]) -> Self {
        Self(base64url::encode(&random))
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// The inputs of the KB-JWT claims transaction data types require: `jti`, the request's
/// `response_mode`, and the signing key's `amr`.
pub struct KbJwtInputs {
    jti: Jti,
    response_mode: ResponseMode,
    amr: Amr,
}

impl KbJwtInputs {
    /// The inputs.
    #[must_use]
    pub fn new(jti: Jti, response_mode: ResponseMode, amr: Amr) -> Self {
        Self {
            jti,
            response_mode,
            amr,
        }
    }
}

impl<'e, 'a> MemberBinding<'e, 'a> {
    /// The credential the entries are bound to.
    #[must_use]
    pub fn presented(&self) -> Presented<'a> {
        self.presented
    }

    /// The entries, in the order of the request.
    #[must_use]
    pub fn entries(&self) -> &[&'e Entry] {
        &self.entries
    }

    /// The claims the entries add to the credential's KB-JWT, which
    /// `siros_sdjwt::Presentation::key_binding` takes as its extra claims (S4):
    /// `transaction_data_hashes`, one hash per entry in the order of the request;
    /// `transaction_data_hashes_alg` when an entry carried `transaction_data_hashes_alg`
    /// (B.3.3.1); then `jti`, `response_mode` and `amr` when an entry's type requires them.
    #[must_use]
    pub fn kb_jwt_claims(&self, inputs: &KbJwtInputs) -> Vec<(String, Value)> {
        let alg = self.choice.alg();
        let hashes = self
            .entries
            .iter()
            .map(|entry| Value::String(alg.hash(entry.raw()).into()))
            .collect();
        let hashes_alg = (self.choice.claim() == AlgClaim::Repeated)
            .then(|| ("transaction_data_hashes_alg", alg.identifier().into()));
        let required = CLAIM_ORDER
            .into_iter()
            .filter(|claim| self.requires(*claim))
            .map(|claim| claim.of(inputs));
        std::iter::once(("transaction_data_hashes", Value::Array(hashes)))
            .chain(hashes_alg)
            .chain(required)
            .map(|(name, value)| (name.to_owned(), value))
            .collect()
    }

    /// Whether an entry bound to the credential requires `claim`.
    fn requires(&self, claim: KbJwtClaim) -> bool {
        self.entries
            .iter()
            .any(|e| e.binding().claims.contains(&claim))
    }

    /// The display of each entry, in the order of [`MemberBinding::entries`], from the type
    /// metadata of the credential, the documents it references in `fetched`, and the user's
    /// locale `preferences`, most preferred first (EC TS12 v1.0.1, Section 3.3).
    ///
    /// # Errors
    ///
    /// [`TransactionDataError`]: the first rule a referenced document or a display breaks.
    pub fn views(
        &self,
        fetched: &Fetched,
        preferences: &[Locale],
    ) -> Result<Step<Vec<TransactionView>>, TransactionDataError> {
        let mut views = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            match self.view(entry, fetched, preferences)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(view) => views.push(view),
            }
        }
        Ok(Step::Done(views))
    }

    /// The display of `entry`, or the fetch of a document it references.
    fn view(
        &self,
        entry: &Entry,
        fetched: &Fetched,
        preferences: &[Locale],
    ) -> Result<Step<TransactionView>, TransactionDataError> {
        let body = entry.body();
        let display = self
            .presented
            .metadata
            .display_metadata(body.identifier())
            .ok_or(TransactionDataError::CredentialUnavailable)?;
        Ok(match display.resolve(fetched)? {
            Step::Fetch(fetch) => Step::Fetch(fetch),
            Step::Done(metadata) => Step::Done(body.display(&metadata, preferences)?),
        })
    }
}
