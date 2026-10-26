//! Each entry bound to one credential of the chosen offer (T4), and what the entries bound to a
//! credential add to its presentation (T3; OpenID4VP 1.0, Section 8.4).

use serde_json::Value;
use siros_codec::base64url;
use siros_credential::Credential;
use siros_display::Locale;
use siros_oid4vp::ResponseMode;

use crate::amr::Amr;
use crate::entry::Entry;
use crate::error::TransactionDataError;
use crate::hash::{Accepted, Choice};
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

/// A credential the chosen offer presents for a Credential Query, with its SCA Attestation
/// metadata.
#[derive(Clone, Copy)]
pub struct Presented<'a> {
    query_id: &'a str,
    metadata: &'a ScaMetadata<'a>,
}

impl<'a> Presented<'a> {
    /// The credential of `metadata`, presented for the Credential Query `query_id`.
    #[must_use]
    pub fn new(query_id: &'a str, metadata: &'a ScaMetadata<'a>) -> Self {
        Self { query_id, metadata }
    }

    /// The Credential Query id.
    #[must_use]
    pub fn query_id(&self) -> &'a str {
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
    let mut bound: Vec<(usize, Vec<&'e Entry>)> = Vec::new();
    for entry in entries {
        let at = authorizing(entry, offer).ok_or(TransactionDataError::CredentialUnavailable)?;
        match bound.iter_mut().find(|(member, _)| *member == at) {
            Some((_, entries)) => entries.push(entry),
            None => bound.push((at, vec![entry])),
        }
    }
    bound.sort_by_key(|(member, _)| *member);
    bound
        .into_iter()
        .map(|(member, entries)| {
            let presented = offer
                .get(member)
                .copied()
                .ok_or(TransactionDataError::CredentialUnavailable)?;
            let accepted: Vec<&Accepted> = entries.iter().map(|e| e.binding().hashes).collect();
            Ok(MemberBinding {
                presented,
                choice: Choice::of(&accepted)?,
                entries,
            })
        })
        .collect()
}

/// The position in `offer` of the credential `entry` binds to.
fn authorizing(entry: &Entry, offer: &[Presented<'_>]) -> Option<usize> {
    let body = entry.body();
    entry.credential_ids().iter().find_map(|id| {
        offer
            .iter()
            .position(|presented| presented.query_id == id && body.authorizes(presented.metadata))
    })
}

/// `jti`: a fresh, random KB-JWT identifier (RFC 7519, Section 4.1.7; EC TS12 v1.0.1, Section
/// 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Jti(String);

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
        &self.0
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
            .map(|entry| Value::String(alg.hash(entry.raw())))
            .collect();
        let mut claims = vec![("transaction_data_hashes".to_owned(), Value::Array(hashes))];
        if self.choice.carried() {
            claims.push((
                "transaction_data_hashes_alg".to_owned(),
                alg.identifier().into(),
            ));
        }
        for claim in CLAIM_ORDER {
            if self
                .entries
                .iter()
                .any(|e| e.binding().claims.contains(&claim))
            {
                claims.push(match claim {
                    KbJwtClaim::Jti => ("jti".to_owned(), inputs.jti.as_str().into()),
                    KbJwtClaim::ResponseMode => (
                        "response_mode".to_owned(),
                        inputs.response_mode.as_str().into(),
                    ),
                    KbJwtClaim::Amr => ("amr".to_owned(), inputs.amr.claim()),
                });
            }
        }
        claims
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
            let body = entry.body();
            let display = self
                .presented
                .metadata
                .display_metadata(body.identifier())
                .ok_or(TransactionDataError::CredentialUnavailable)?;
            match display.resolve(fetched)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(metadata) => views.push(body.display(&metadata, preferences)?),
            }
        }
        Ok(Step::Done(views))
    }
}
