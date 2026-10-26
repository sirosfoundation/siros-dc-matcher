//! The consent view: the verifier, and per offer its purposes, its credentials with their
//! claim or proof statement rows, its additions and its transactions.

use siros_dcql::Dropped;
use siros_display::proof::{verified_rows, ProofRow};
use siros_display::{purpose, Card, ClaimRow, DisplayCache, Locale};
use siros_oid4vp::VerifierView;
use siros_transaction_data::{Fetched, Step, TransactionView};
use siros_wallet_state::CredentialId;

use super::transactions::{Transactions, Wallet};
use crate::display_rule::{DisplayFacts, WalletDisplay};
use crate::error::PresentationError;
use crate::matching::Answer;
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
        let mut bound = Vec::with_capacity(member.candidates().len());
        for &candidate in member.candidates() {
            let mut entries = Vec::new();
            let mut transactions = Vec::new();
            let fail = PresentationError::TransactionData;
            for (_, binding) in bindings.iter().filter(|(key, _)| *key == (at, candidate)) {
                match binding
                    .views(sources.fetched, sources.locales)
                    .map_err(fail)?
                {
                    Step::Fetch(fetch) => return Ok(Step::Fetch(fetch)),
                    Step::Done(views) => transactions.extend(views),
                }
                entries.extend(sources.transactions.positions(binding).map_err(fail)?);
            }
            bound.push((entries, transactions));
        }
        members.push(member_view(member, bound, sources)?);
    }
    let additions = offer
        .additions()
        .iter()
        .map(|addition| {
            Ok(AdditionView {
                purpose: addition
                    .purpose()
                    .and_then(|p| purpose::line(std::slice::from_ref(p))),
                members: addition
                    .members()
                    .iter()
                    .map(|member| member_view(member, Vec::new(), sources))
                    .collect::<Result<_, PresentationError>>()?,
            })
        })
        .collect::<Result<Vec<_>, PresentationError>>()?;
    let mut presentable = true;
    for member in offer.members() {
        for id in credential_ids(sources.answered, member)? {
            presentable &= sources.background.contains(&id);
        }
    }
    let facts = DisplayFacts {
        presentable_without_ui: presentable,
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

/// The `credentialId` of each instance `member` presents.
fn credential_ids(
    answered: &Wallet<'_>,
    member: &Member,
) -> Result<Vec<CredentialId>, PresentationError> {
    let answers = answered
        .queries()
        .get(member.query())
        .ok_or(PresentationError::AnswerMismatch)?;
    member
        .candidates()
        .iter()
        .map(|&index| {
            let candidate = answers
                .candidates()
                .get(index)
                .ok_or(PresentationError::AnswerMismatch)?;
            Ok(candidate.credential().credential().entry().credential_id())
        })
        .collect()
}

/// The view of `member`, with the positions and the views of the entries bound to each of its
/// credentials; none bound when `bound` is empty.
fn member_view(
    member: &Member,
    mut bound: Vec<(Vec<usize>, Vec<TransactionView>)>,
    sources: &Sources<'_, '_>,
) -> Result<MemberView, PresentationError> {
    let answers = sources
        .answered
        .queries()
        .get(member.query())
        .ok_or(PresentationError::AnswerMismatch)?;
    bound.resize_with(member.candidates().len(), Default::default);
    let mut credentials = Vec::with_capacity(member.candidates().len());
    for (&index, (entries, transactions)) in member.candidates().iter().zip(bound) {
        let candidate = answers
            .candidates()
            .get(index)
            .ok_or(PresentationError::AnswerMismatch)?;
        let credential = candidate.credential().credential();
        let display = PresentationError::Display;
        let shown = match candidate.answer() {
            Answer::Claims(claims) => Shown::Claims(
                sources
                    .display
                    .claim_rows(credential, claims.pointers(), sources.locales)
                    .map_err(display)?,
            ),
            Answer::Proof(choice) => {
                let zkp = answers.zkp().ok_or(PresentationError::AnswerMismatch)?;
                let option = zkp
                    .option(choice)
                    .ok_or(PresentationError::AnswerMismatch)?;
                Shown::Proof(verified_rows(zkp.query().query(), option).map_err(display)?)
            }
        };
        credentials.push(CredentialView {
            card: sources
                .display
                .card(credential, sources.locales)
                .map_err(display)?,
            shown,
            entries,
            transactions,
        });
    }
    Ok(MemberView {
        query_id: answers.query().id.clone(),
        credentials,
    })
}
