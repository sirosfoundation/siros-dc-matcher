//! The consent view: the verifier, and per offer its purposes, its credentials with their
//! claim or proof statement rows, its additions and its transactions.

use siros_credential::UsableCredential;
use siros_dcql::Dropped;
use siros_display::proof::{verified_rows, ProofRow};
use siros_display::{purpose, Card, ClaimRow, DisplayCache, Locale};
use siros_oid4vp::VerifierView;
use siros_transaction_data::{Fetched, MemberBinding, Step, TransactionView};
use siros_wallet_state::CredentialId;

use super::transactions::{Bound, Transactions, Wallet};
use crate::display_rule::{DisplayFacts, WalletDisplay};
use crate::error::PresentationError;
use crate::matching::{Answer, Answers, Candidate};
use crate::offers::{Member, Offer, Offers};

/// What the user consents to. It holds no delivered secret and no undisclosable attribute.
pub struct ConsentView<'a> {
    verifier: VerifierView<'a>,
    digest: String,
    offers: Vec<OfferView>,
    unexamined: Dropped,
}

/// An offer as the user sees it.
pub struct OfferView {
    purpose: Option<String>,
    members: Vec<MemberView>,
    additions: Vec<AdditionView>,
    unexamined: Dropped,
    wallet_display: WalletDisplay,
}

/// An addition as the user sees it.
pub struct AdditionView {
    set: usize,
    purpose: Option<String>,
    members: Vec<MemberView>,
}

/// A member of an offer as the user sees it: its Credential Query and its credentials, one
/// unless the query sets `multiple`.
pub struct MemberView {
    query_id: String,
    credentials: Vec<CredentialView>,
}

/// A credential of a member as the user sees it.
pub struct CredentialView {
    credential_id: CredentialId,
    answer: Answer,
    card: Card,
    shown: Shown,
    entries: Vec<usize>,
    transactions: Vec<TransactionView>,
}

/// What a member shows of its credential.
pub enum Shown {
    /// The rows of the claims it discloses.
    Claims(Vec<ClaimRow>),
    /// The proof statement rows of the `zkp_req` option it answers.
    Proof(Vec<ProofRow>),
}

impl<'a> ConsentView<'a> {
    /// Who asks.
    pub fn verifier(&self) -> VerifierView<'a> {
        self.verifier
    }

    /// The plan's digest, unpadded base64url, which the selection returns (A4).
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The offers, in the plan's order.
    pub fn offers(&self) -> &[OfferView] {
        &self.offers
    }

    /// How many combinations were not examined for offers.
    pub fn unexamined(&self) -> Dropped {
        self.unexamined
    }
}

impl OfferView {
    /// The purposes of the credential sets the offer satisfies, as one line (Section 6.2).
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    /// The credentials.
    pub fn members(&self) -> &[MemberView] {
        &self.members
    }

    /// The additions the user may choose.
    pub fn additions(&self) -> &[AdditionView] {
        &self.additions
    }

    /// How many combinations of the optional sets were not examined for additions.
    pub fn unexamined(&self) -> Dropped {
        self.unexamined
    }

    /// Whether the offer needs the wallet's display (A9).
    pub fn wallet_display(&self) -> WalletDisplay {
        self.wallet_display
    }
}

impl AdditionView {
    /// The index of the addition's credential set in `credential_sets`.
    pub(super) fn set(&self) -> usize {
        self.set
    }

    /// The purpose of the addition's credential set.
    pub fn purpose(&self) -> Option<&str> {
        self.purpose.as_deref()
    }

    /// The credentials.
    pub fn members(&self) -> &[MemberView] {
        &self.members
    }
}

impl MemberView {
    /// The Credential Query the member answers.
    pub fn query_id(&self) -> &str {
        &self.query_id
    }

    /// The credentials, in the order of the member's candidates: the selection chooses a
    /// subset of them by their positions here.
    pub fn credentials(&self) -> &[CredentialView] {
        &self.credentials
    }
}

impl CredentialView {
    /// The instance presented.
    pub(super) fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// What the instance presents.
    pub(super) fn answer(&self) -> &Answer {
        &self.answer
    }

    /// The credential's card.
    pub fn card(&self) -> &Card {
        &self.card
    }

    /// What the credential shows.
    pub fn shown(&self) -> &Shown {
        &self.shown
    }

    /// The positions in the request's `transaction_data` of the entries bound to the credential
    /// (T4), in the order of the request.
    pub fn entries(&self) -> &[usize] {
        &self.entries
    }

    /// The transactions the credential authorizes: the display of each of its entries.
    pub fn transactions(&self) -> &[TransactionView] {
        &self.transactions
    }
}

/// What the view is built from.
pub(crate) struct Sources<'s, 'a> {
    pub(crate) answered: &'s Wallet<'a>,
    pub(crate) transactions: &'s Transactions<'a>,
    pub(crate) display: &'s DisplayCache,
    pub(crate) locales: &'s [Locale],
    pub(crate) background: &'s [CredentialId],
    pub(crate) fetched: &'s Fetched,
    pub(crate) transaction_data: bool,
}

impl<'a> ConsentView<'a> {
    /// The view of `offers`, before its digest. The step is a fetch while a transaction's
    /// display references a document the host has not given.
    pub(crate) fn build(
        verifier: VerifierView<'a>,
        offers: &Offers,
        sources: &Sources<'_, 'a>,
    ) -> Result<Step<Self>, PresentationError> {
        let mut views = Vec::with_capacity(offers.offers().len());
        for offer in offers.offers() {
            match offer_view(offer, sources)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(view) => views.push(view),
            }
        }
        Ok(Step::Done(Self {
            verifier,
            digest: String::new(),
            offers: views,
            unexamined: offers.unexamined(),
        }))
    }

    pub(crate) fn with_digest(mut self, digest: String) -> Self {
        self.digest = digest;
        self
    }
}

fn offer_view(
    offer: &Offer,
    sources: &Sources<'_, '_>,
) -> Result<Step<OfferView>, PresentationError> {
    let bindings = sources
        .transactions
        .bind(sources.answered, offer.members())?;
    let mut members = Vec::with_capacity(offer.members().len());
    for (at, member) in offer.members().iter().enumerate() {
        match member_view(member, at, &bindings, sources)? {
            Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
            Step::Done(view) => members.push(view),
        }
    }
    let mut additions = Vec::with_capacity(offer.additions().len());
    for addition in offer.additions() {
        let mut views = Vec::with_capacity(addition.members().len());
        for (at, member) in addition.members().iter().enumerate() {
            match member_view(member, at, &[], sources)? {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(view) => views.push(view),
            }
        }
        additions.push(AdditionView {
            set: addition.set(),
            purpose: addition
                .purpose()
                .and_then(|p| purpose::line(std::slice::from_ref(p))),
            members: views,
        });
    }
    let facts = DisplayFacts {
        presentable_without_ui: members
            .iter()
            .flat_map(MemberView::credentials)
            .all(|c| sources.background.contains(&c.credential_id)),
        transaction_data: sources.transaction_data,
        // Each disclosed claim and each proof statement has a row of `DisplayText`, which holds
        // its text whole.
        rows_whole: true,
        additions: !additions.is_empty(),
        multiple: offer.members().iter().any(|m| m.candidates().len() > 1),
    };
    Ok(Step::Done(OfferView {
        purpose: purpose::line(offer.purposes()),
        members,
        additions,
        unexamined: offer.unexamined(),
        wallet_display: WalletDisplay::of(&facts),
    }))
}

/// The view of `member`, at position `at` of its offer, with the entries `bindings` bind to
/// each of its credentials.
fn member_view(
    member: &Member,
    at: usize,
    bindings: &[(Bound, MemberBinding<'_, '_>)],
    sources: &Sources<'_, '_>,
) -> Result<Step<MemberView>, PresentationError> {
    let answers = sources
        .answered
        .queries()
        .get(member.query())
        .ok_or(PresentationError::AnswerMismatch)?;
    let mut credentials = Vec::with_capacity(member.candidates().len());
    for &index in member.candidates() {
        let candidate = answers
            .candidates()
            .get(index)
            .ok_or(PresentationError::AnswerMismatch)?;
        let mut entries = Vec::new();
        let mut transactions = Vec::new();
        let fail = PresentationError::TransactionData;
        for (_, binding) in bindings.iter().filter(|(key, _)| *key == (at, index)) {
            match binding
                .views(sources.fetched, sources.locales)
                .map_err(fail)?
            {
                Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                Step::Done(views) => transactions.extend(views),
            }
            entries.extend(sources.transactions.positions(binding).map_err(fail)?);
        }
        let credential = candidate.credential().credential();
        credentials.push(CredentialView {
            credential_id: credential.entry().credential_id(),
            answer: candidate.answer().clone(),
            card: sources
                .display
                .card(credential, sources.locales)
                .map_err(PresentationError::Display)?,
            shown: shown(answers, candidate, sources)?,
            entries,
            transactions,
        });
    }
    Ok(Step::Done(MemberView {
        query_id: answers.query().id.clone(),
        credentials,
    }))
}

/// What `candidate`, a candidate of `answers`, shows: its claim rows or its proof statement
/// rows.
fn shown<'a>(
    answers: &Answers<'a, UsableCredential<'a>>,
    candidate: &Candidate<UsableCredential<'a>>,
    sources: &Sources<'_, 'a>,
) -> Result<Shown, PresentationError> {
    let display = PresentationError::Display;
    Ok(match candidate.answer() {
        Answer::Claims(claims) => Shown::Claims(
            sources
                .display
                .claim_rows(
                    candidate.credential().credential(),
                    claims.pointers(),
                    sources.locales,
                )
                .map_err(display)?,
        ),
        Answer::Proof(choice) => {
            let zkp = answers.zkp().ok_or(PresentationError::AnswerMismatch)?;
            let option = zkp
                .option(choice)
                .ok_or(PresentationError::AnswerMismatch)?;
            Shown::Proof(verified_rows(zkp.query().query(), option).map_err(display)?)
        }
    })
}
