//! Phase 1: the plan of a verified request over the wallet's usable credentials, and its consent
//! view.

mod digest;
mod fetches;
mod seed;
mod transactions;
mod view;

use rand_core::CryptoRngCore;
use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_credential::{Credential, Parsed, UsableCredential};
use siros_display::{DisplayCache, Locale};
use siros_oid4vp::{ErrorCode, Fetch, Submission, VerifiedRequest};
use siros_transaction_data::{Amr, Step, TransactionDataError};
use siros_wallet_state::{CredentialId, KeyId, PresentationRecord};
use siros_zkp_req_nym_auth::attestation::UsableAttestation;
use siros_zkp_req_nym_auth::presenter::Answer as NymAnswer;
use siros_zkp_req_nym_auth::request::NymAuthRequest;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;
use zeroize::Zeroizing;

use crate::error::PresentationError;
use crate::matching::{Asked, Matching, ProofChoice, ZkpQuery};
use crate::offers::Offers;
use transactions::{Transactions, Wallet};
use view::Sources;

pub use fetches::Fetches;
pub use view::{AdditionView, ConsentView, MemberView, OfferView, Shown};

/// What a plan is made from. Phase 2 makes the plan again from the same input.
#[derive(Clone, Copy)]
pub struct PlanInput<'a> {
    /// The request intake verified.
    pub request: &'a VerifiedRequest,
    /// The wallet's credentials. The plan presents those usable at `now` (C4).
    pub credentials: &'a [Credential],
    /// The wallet's presentation records, which choose the instance of each batch (C5).
    pub records: &'a [PresentationRecord],
    /// The display metadata the host holds.
    pub display: &'a DisplayCache,
    /// The user's locales, most preferred first.
    pub locales: &'a [Locale],
    /// The nym_auth systems whose circuits the host loaded, in the wallet's order of
    /// preference.
    pub systems: &'a [NymAuthSystem],
    /// The form of `verifier_id` the Verifier's trust framework fixes, for a nym_auth query.
    pub verifier_id: VerifierIdForm,
    /// The credentials the wallet declares presentable without its UI (A9).
    pub background: &'a [CredentialId],
    /// The authentication factors of each signing key the host reported (H3).
    pub key_factors: &'a [(KeyId, Amr)],
    /// The host's responses to the fetches the plan asked for.
    pub fetches: &'a Fetches,
    /// The time: the proof time of a nym_auth proof and the `iat` of a KB-JWT.
    pub now: DateTime,
}

/// What a step of planning gives.
pub enum PlanStep<'a> {
    /// A document for the host to fetch. Its response goes to [`Fetches::answer`], and the plan
    /// is made again.
    Fetch(Fetch),
    /// The plan.
    Ready(Box<Planned<'a>>),
}

/// The plan of a request: its offers, their consent view, and its digest.
pub struct Planned<'a> {
    pub(crate) input: PlanInput<'a>,
    pub(crate) nym_auth: Option<NymAuthRequest<'a>>,
    pub(crate) answered: Wallet<'a>,
    pub(crate) transactions: Transactions<'a>,
    pub(crate) offers: Offers,
    pub(crate) digest: [u8; 32],
    pub(crate) view: ConsentView<'a>,
}

/// The plan of `input` (phase 1).
///
/// The request's `transaction_data` entries are read at `now`. The credentials are matched
/// (A1, A2); a nym_auth candidate answers the first option with a usable pair whose
/// [`NymAnswer`] holds: a usable attestation at `now`, its `secret_seed` from the delivered
/// auxiliary data, and the option's assertions (N3, N4). Of the offers (A3), those that bind
/// every entry are kept (T4). The view shows each member's card and claim rows or verified proof
/// statement rows, and the transactions bound to it.
///
/// # Errors
///
/// [`PresentationError::NoOffer`] with the request's code when no offer remains, and the first
/// transaction data or display rule the input breaks.
pub fn plan<'a>(input: &PlanInput<'a>) -> Result<PlanStep<'a>, PresentationError> {
    let request = input.request;
    let nym_auth = NymAuthRequest::new(request, input.verifier_id);
    let policy = nym_auth.as_ref().map(|_| ()).map_err(|refusal| *refusal);
    let asked = Asked::new(
        request.dcql_query(),
        request.dcql_query_json(),
        request.client_metadata(),
    );
    let usable: Vec<UsableCredential<'a>> = input
        .credentials
        .iter()
        .filter_map(|credential| UsableCredential::at(credential, input.now).ok())
        .collect();
    let answered = Matching::new(
        asked,
        &usable,
        input.records,
        input.systems,
        input.now.date(),
        policy,
    )
    .answer(|credential, zkp| {
        let (attestation, seed) = tested(credential, zkp, input.now)?;
        zkp.choices().iter().position(|choice| {
            zkp.pair(choice)
                .is_some_and(|pair| NymAnswer::new(pair, attestation.clone(), &seed).is_ok())
        })
    });
    let transactions = match Transactions::read(request, &answered, input.fetches, input.now)? {
        Step::Fetch(fetch) => return Ok(PlanStep::Fetch(fetch)),
        Step::Done(transactions) => transactions,
    };
    let mut refused = None;
    let offers = Offers::of(
        &answered,
        |members| match transactions.bind(&answered, members) {
            Ok(_) => true,
            Err(error) => {
                if refused.is_none() {
                    refused = Some(error);
                }
                false
            }
        },
        |query| transactions.names(query),
    );
    if offers.offers().is_empty() {
        return Err(match refused {
            Some(error) => PresentationError::TransactionData(error),
            None if transactions.unavailable(&answered) => {
                PresentationError::TransactionData(TransactionDataError::CredentialUnavailable)
            }
            None => PresentationError::NoOffer(error_code(answered.failure())),
        });
    }
    let fetched = input.fetches.fetched();
    let sources = Sources {
        answered: &answered,
        transactions: &transactions,
        display: input.display,
        locales: input.locales,
        background: input.background,
        fetched: &fetched,
        transaction_data: !request.transaction_data().is_empty(),
    };
    let view = match ConsentView::build(request.verifier(), &offers, &sources)? {
        Step::Fetch(fetch) => return Ok(PlanStep::Fetch(fetch)),
        Step::Done(view) => view,
    };
    let digest = digest::digest(request, &answered, &offers, view.offers())?;
    let view = view.with_digest(base64url::encode(&digest));
    Ok(PlanStep::Ready(Box::new(Planned {
        input: *input,
        nym_auth: nym_auth.ok(),
        answered,
        transactions,
        offers,
        digest,
        view,
    })))
}

impl<'a> Planned<'a> {
    /// The consent view.
    pub fn view(&self) -> &ConsentView<'a> {
        &self.view
    }

    /// The submission of the user's decline: `access_denied` (A8).
    ///
    /// # Errors
    ///
    /// [`PresentationError::Response`] when the error response cannot be encrypted.
    pub fn decline(&self, rng: &mut impl CryptoRngCore) -> Result<Submission, PresentationError> {
        refusal(self.input.request, ErrorCode::AccessDenied, rng)
    }
}

/// The submission refusing `request` with `code`, an error's
/// [`PresentationError::error_code`] (P5: the response target of a verified request is
/// verified).
///
/// # Errors
///
/// [`PresentationError::Response`] when the error response cannot be encrypted.
pub fn refusal(
    request: &VerifiedRequest,
    code: ErrorCode,
    rng: &mut impl CryptoRngCore,
) -> Result<Submission, PresentationError> {
    request
        .error_submission(code, rng)
        .map_err(PresentationError::Response)
}

/// The answer of `choice` by `credential` at `now`, which opens the attestation's `ssc` for
/// this use.
pub(crate) fn nym_answer<'z>(
    credential: &UsableCredential<'_>,
    zkp: &'z ZkpQuery,
    choice: &ProofChoice,
    now: DateTime,
) -> Option<NymAnswer<'z>> {
    let (attestation, seed) = tested(credential, zkp, now)?;
    NymAnswer::new(zkp.pair(choice)?, attestation, &seed).ok()
}

/// The usable attestation of `credential`'s mdoc for `zkp` at `now`, and the `secret_seed` its
/// issuer delivered.
fn tested(
    credential: &UsableCredential<'_>,
    zkp: &ZkpQuery,
    now: DateTime,
) -> Option<(UsableAttestation, Zeroizing<[u8; 16]>)> {
    let Parsed::Mdoc(mdoc) = credential.credential().parsed() else {
        return None;
    };
    // No input resolves `trusted_authorities` to anchors: a query that names authorities finds
    // every issuer untrusted.
    let anchors = zkp
        .query()
        .query()
        .trusted_authorities
        .as_ref()
        .map(|_| &[][..]);
    let attestation = UsableAttestation::of(mdoc, anchors, now).ok()?;
    let seed = seed::delivered(credential.credential()).ok()?;
    Some((attestation, seed))
}

/// The OpenID4VP 1.0, Section 8.5 code of a `zkp_req.md`, Section 5 code.
fn error_code(code: siros_zkp_req::ErrorCode) -> ErrorCode {
    match code {
        siros_zkp_req::ErrorCode::InvalidRequest => ErrorCode::InvalidRequest,
        siros_zkp_req::ErrorCode::VpFormatsNotSupported => ErrorCode::VpFormatsNotSupported,
        siros_zkp_req::ErrorCode::AccessDenied => ErrorCode::AccessDenied,
    }
}
