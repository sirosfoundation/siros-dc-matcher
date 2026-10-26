//! Phase 1: the plan of a verified request over the wallet's usable credentials, and its consent
//! view.

/// The value of the planning step `step`, or the fetch it waits for, which the enclosing
/// function returns at once.
macro_rules! fetched {
    ($step:expr) => {
        match $step {
            siros_transaction_data::Step::Fetch(fetch) => {
                return Ok(siros_transaction_data::Step::Fetch(fetch))
            }
            siros_transaction_data::Step::Done(value) => value,
        }
    };
}

mod digest;
mod fetches;
mod proof;
mod seed;
mod transactions;
mod view;

use rand_core::CryptoRngCore;
use siros_codec::date::DateTime;
use siros_credential::{Credential, UsableCredential};
use siros_display::{DisplayCache, Locale};
use siros_oid4vp::{ErrorCode, Fetch, Submission, VerifiedRequest};
use siros_transaction_data::{Amr, Step, TransactionDataError};
use siros_trust::TrustStore;
use siros_wallet_state::{CredentialId, KeyId, PresentationRecord};
use siros_zkp_req_nym_auth::policy::RequestRefusal;
use siros_zkp_req_nym_auth::request::NymAuthRequest;
use siros_zkp_req_nym_auth::system::NymAuthSystem;
use siros_zkp_req_nym_auth::verifier_id::VerifierIdForm;

use crate::display_rule::TransactionData;
use crate::error::PresentationError;
use crate::matching::{Asked, Matching};
use crate::offers::{Offers, Refusal};
use transactions::{Transactions, Wallet};
use view::Sources;

pub use digest::{DigestError, PlanDigest};
pub use fetches::Fetches;
pub(crate) use proof::nym_answer;
pub use proof::{OptionRefusal, Unproven};
pub use seed::{JsonCause, NoSeed};
pub use transactions::EntryPosition;
pub(crate) use transactions::{offered, Bound, Offered};
pub use view::{AdditionView, ConsentView, CredentialView, MemberView, OfferView, Shown};

/// What a plan is made from. Phase 2 makes the plan again from the same input.
#[derive(Clone, Copy)]
pub struct PlanInput<'a> {
    /// The request intake verified.
    pub request: &'a VerifiedRequest,
    /// The wallet's credentials. The plan presents those usable at `now` (C4).
    pub credentials: &'a [Credential],
    /// The trust store the host provisions (H4, TR4), which resolves `trusted_authorities`.
    pub trust: &'a TrustStore,
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

/// The plan of a request: its offers, and their consent view with its digest.
pub struct Planned<'a> {
    pub(crate) input: PlanInput<'a>,
    pub(crate) nym_auth: Result<NymAuthRequest<'a>, RequestRefusal>,
    pub(crate) answered: Wallet<'a>,
    pub(crate) transactions: Transactions<'a>,
    pub(crate) view: ConsentView<'a>,
}

/// The plan of `input` (phase 1).
///
/// The request's `transaction_data` entries are read at `now`. The credentials usable at `now`
/// are matched (A1, A2); a nym_auth candidate answers the first option with a usable pair whose
/// answer holds: a usable attestation at `now`, its `secret_seed` from the delivered auxiliary
/// data, and the option's assertions (N3, N4). Of the offers (A3), those that bind every entry
/// are kept (T4). The view shows each member's card and claim rows or verified proof statement
/// rows, and the transactions bound to it.
///
/// # Errors
///
/// [`PresentationError::NoOffer`] with the reason when no offer remains, and the first rule
/// the request, its transaction data or the display breaks.
pub fn plan<'a>(input: &PlanInput<'a>) -> Result<PlanStep<'a>, PresentationError> {
    Ok(match planned(input)? {
        Step::Fetch(fetch) => PlanStep::Fetch(fetch),
        Step::Done(planned) => PlanStep::Ready(Box::new(planned)),
    })
}

fn planned<'a>(input: &PlanInput<'a>) -> Result<Step<Planned<'a>>, PresentationError> {
    let request = input.request;
    let nym_auth = NymAuthRequest::new(request, input.verifier_id);
    let policy = nym_auth.as_ref().map(drop).map_err(|refusal| *refusal);
    let answered = answered(input, policy)?;
    let transactions = fetched!(Transactions::read(
        request,
        &answered,
        input.fetches,
        input.now
    )?);
    let offers = offers(&answered, &transactions)?;
    let sources = Sources {
        answered: &answered,
        transactions: &transactions,
        display: input.display,
        locales: input.locales,
        background: input.background,
        fetched: input.fetches.fetched(),
        transaction_data: if request.transaction_data().is_empty() {
            TransactionData::Absent
        } else {
            TransactionData::Carried
        },
    };
    let views = fetched!(view::offer_views(&offers, &sources)?);
    // A request that is no nym_auth request has no `verifier_id`.
    let verifier_id = nym_auth
        .as_ref()
        .ok()
        .map(|nym_auth| &nym_auth.session().verifier_id);
    let digest = PlanDigest::of(request, verifier_id, &views);
    let view = ConsentView::new(request.verifier(), digest, views, offers.unexamined());
    Ok(Step::Done(Planned {
        input: *input,
        nym_auth,
        answered,
        transactions,
        view,
    }))
}

/// The candidates of each Credential Query of `input`'s request, over the credentials usable at
/// `now` (C4) whose issuer the query's `trusted_authorities` admit against the trust store at
/// `now` (TR3). Each `zkp_req` candidate answers the first option its tests pass; `policy` says
/// whether the request meets the nym_auth policy.
fn answered<'a>(
    input: &PlanInput<'a>,
    policy: Result<(), RequestRefusal>,
) -> Result<Wallet<'a>, PresentationError> {
    let request = input.request;
    let asked = Asked::new(
        request.dcql_query(),
        request.dcql_query_json(),
        request.client_metadata(),
    )?;
    let usable: Vec<UsableCredential<'a>> = input
        .credentials
        .iter()
        .filter_map(|credential| UsableCredential::at(credential, input.now).ok())
        .collect();
    let matching = Matching::new(
        asked,
        &usable,
        input.trust,
        input.records,
        input.systems,
        input.now.date(),
        policy,
    );
    Ok(matching.answer(|credential, issuer, zkp| {
        proof::first_answered(credential, issuer, zkp, input.now)
    }))
}

/// The offers of `answered` whose credentials bind every entry of `transactions` (T4).
///
/// # Errors
///
/// [`PresentationError`] when no offer remains: the first binding refused, or
/// [`TransactionDataError::CredentialUnavailable`] for an offer that cannot carry every entry,
/// whichever came first; an entry whose queries no credential answers; or why the request has
/// no offer.
fn offers<'a>(
    answered: &Wallet<'a>,
    transactions: &Transactions<'a>,
) -> Result<Offers, PresentationError> {
    let entries = transactions.carriers(answered);
    let (offers, refusal) = Offers::of(answered, &entries, |members| {
        transactions.bind(answered, members).map(drop)
    });
    if !offers.offers().is_empty() {
        return Ok(offers);
    }
    match refusal {
        Some(Refusal::Refused(refusal)) => return Err(refusal),
        Some(Refusal::Uncarried) => return Err(TransactionDataError::CredentialUnavailable.into()),
        None => {}
    }
    transactions.available(answered)?;
    Err(answered.failure().into())
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
    Ok(request.error_submission(code, rng)?)
}
