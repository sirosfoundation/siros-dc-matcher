//! The consent view: the verifier, and per offer its purposes, its credentials with their
//! claim or proof statement rows, its additions and its transactions.

use siros_dcql::Dropped;
use siros_display::proof::{verified_rows, ProofRow};
use siros_display::{purpose, Card, ClaimRow, DisplayCache, Locale};
use siros_oid4vp::VerifierView;
use siros_transaction_data::{Fetched, MemberBinding, Step, TransactionView};
use siros_wallet_state::CredentialId;

use super::digest::PlanDigest;
use super::transactions::{offered, Bound, EntryPosition, Offered, Transactions, Wallet};
use crate::display_rule::{Choice, DisplayFacts, Presentability, TransactionData, WalletDisplay};
use crate::error::{Inconsistency, PresentationError};
use crate::ids::SetIndex;
use crate::matching::{Answer, Candidate};
use crate::offers::{Addition, Member, Offer, Offers};
use siros_dcql::QueryId;

/// What the user consents to. It holds no delivered secret and no undisclosable attribute.
pub struct ConsentView<'a> {
    verifier: VerifierView<'a>,
    digest: PlanDigest,
    offers: Vec<OfferView>,
    unexamined: Dropped,
}

/// An offer as the user sees it.
pub struct OfferView {
    offer: Offer,
    purpose: Option<String>,
    members: Vec<MemberView>,
    additions: Vec<AdditionView>,
    unexamined: Dropped,
    wallet_display: WalletDisplay,
}

/// An addition as the user sees it.
pub struct AdditionView {
    set: SetIndex,
    purpose: Option<String>,
    members: Vec<MemberView>,
}

/// A member of an offer as the user sees it: its Credential Query and its credentials, one
/// unless the query sets `multiple`.
pub struct MemberView {
    query_id: QueryId,
    credentials: Vec<CredentialView>,
}

/// A credential of a member as the user sees it.
pub struct CredentialView {
    credential_id: CredentialId,
    answer: Answer,
    card: Card,
    shown: Shown,
    entries: Vec<EntryPosition>,
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
    /// The view of the request of `verifier`, whose offers show as `offers`, with the plan's
    /// `digest`.
    pub(crate) fn new(
        verifier: VerifierView<'a>,
        digest: PlanDigest,
        offers: Vec<OfferView>,
        unexamined: Dropped,
    ) -> Self {
        Self {
            verifier,
            digest,
            offers,
            unexamined,
        }
    }

    /// Who asks.
    pub fn verifier(&self) -> VerifierView<'a> {
        self.verifier
    }

    /// The plan's digest, which the selection returns (A4).
    pub fn digest(&self) -> &PlanDigest {
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
    /// The offer of the plan the view shows.
    pub(crate) fn offer(&self) -> &Offer {
        &self.offer
    }

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
    /// The position of the addition's credential set in `credential_sets`.
    pub fn set(&self) -> SetIndex {
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
    pub fn query_id(&self) -> &QueryId {
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
    pub(crate) fn credential_id(&self) -> CredentialId {
        self.credential_id
    }

    /// What the instance presents.
    pub(crate) fn answer(&self) -> &Answer {
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
    pub fn entries(&self) -> &[EntryPosition] {
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
    pub(crate) transaction_data: TransactionData,
}

/// The view of each of `offers`. The step is a fetch while a transaction's display references
/// a document the host has not given.
pub(crate) fn offer_views(
    offers: &Offers,
    sources: &Sources<'_, '_>,
) -> Result<Step<Vec<OfferView>>, PresentationError> {
    let mut views = Vec::with_capacity(offers.offers().len());
    for offer in offers.offers() {
        views.push(fetched!(offer_view(offer, sources)?));
    }
    Ok(Step::Done(views))
}

fn offer_view(
    offer: &Offer,
    sources: &Sources<'_, '_>,
) -> Result<Step<OfferView>, PresentationError> {
    let bindings = sources
        .transactions
        .bind(sources.answered, offer.members())?;
    let members = fetched!(member_views(offer.members(), &bindings, sources)?);
    let mut additions = Vec::with_capacity(offer.additions().len());
    for addition in offer.additions() {
        additions.push(fetched!(addition_view(addition, sources)?));
    }
    let facts = DisplayFacts {
        presentability: presentability(&members, sources.background),
        transaction_data: sources.transaction_data,
        additions: if additions.is_empty() {
            Choice::Settled
        } else {
            Choice::Open
        },
        subsets: if offer.members().iter().any(|m| m.candidates().len() > 1) {
            Choice::Open
        } else {
            Choice::Settled
        },
    };
    Ok(Step::Done(OfferView {
        offer: offer.clone(),
        purpose: purpose::line(offer.purposes()),
        members,
        additions,
        unexamined: offer.unexamined(),
        wallet_display: WalletDisplay::of(&facts),
    }))
}

fn addition_view(
    addition: &Addition,
    sources: &Sources<'_, '_>,
) -> Result<Step<AdditionView>, PresentationError> {
    let members = fetched!(member_views(addition.members(), &[], sources)?);
    Ok(Step::Done(AdditionView {
        set: addition.set(),
        purpose: addition
            .purpose()
            .and_then(|p| purpose::line(std::slice::from_ref(p))),
        members,
    }))
}

/// Whether the wallet presents each credential of `members` from its background service.
fn presentability(members: &[MemberView], background: &[CredentialId]) -> Presentability {
    let presentable = members
        .iter()
        .flat_map(MemberView::credentials)
        .all(|credential| background.contains(&credential.credential_id));
    if presentable {
        Presentability::WithoutUi
    } else {
        Presentability::OnWalletUi
    }
}

/// The views of `members`, with the entries `bindings` bind to each of their credentials.
fn member_views(
    members: &[Member],
    bindings: &[(Bound, MemberBinding<'_, '_>)],
    sources: &Sources<'_, '_>,
) -> Result<Step<Vec<MemberView>>, PresentationError> {
    let mut views = Vec::with_capacity(members.len());
    for member in offered(sources.answered, members)? {
        let mut credentials = Vec::with_capacity(member.candidates.len());
        for &(index, candidate) in &member.candidates {
            let bound = fetched!(bound_entries(bindings, member.bound(index), sources)?);
            credentials.push(credential_view(&member, candidate, bound, sources)?);
        }
        views.push(MemberView {
            query_id: member.answers.id().clone(),
            credentials,
        });
    }
    Ok(Step::Done(views))
}

/// The entries bound to one credential: their positions, and their displays.
struct BoundEntries {
    entries: Vec<EntryPosition>,
    transactions: Vec<TransactionView>,
}

/// The entries `bindings` bind to the credential `bound`.
fn bound_entries(
    bindings: &[(Bound, MemberBinding<'_, '_>)],
    bound: Bound,
    sources: &Sources<'_, '_>,
) -> Result<Step<BoundEntries>, PresentationError> {
    let mut entries = Vec::new();
    let mut transactions = Vec::new();
    for (_, binding) in bindings.iter().filter(|(key, _)| *key == bound) {
        transactions.extend(fetched!(binding.views(sources.fetched, sources.locales)?));
        entries.extend(sources.transactions.positions(binding)?);
    }
    Ok(Step::Done(BoundEntries {
        entries,
        transactions,
    }))
}

/// The view of `candidate`, a candidate of `member`, with the entries bound to it.
fn credential_view(
    member: &Offered<'_, '_>,
    candidate: &Candidate<siros_credential::UsableCredential<'_>>,
    bound: BoundEntries,
    sources: &Sources<'_, '_>,
) -> Result<CredentialView, PresentationError> {
    let credential = candidate.credential().credential();
    Ok(CredentialView {
        credential_id: credential.entry().credential_id(),
        answer: candidate.answer().clone(),
        card: sources.display.card(credential, sources.locales)?,
        shown: shown(member, candidate, sources)?,
        entries: bound.entries,
        transactions: bound.transactions,
    })
}

/// What `candidate`, a candidate of `member`, shows: its claim rows or its proof statement
/// rows.
fn shown(
    member: &Offered<'_, '_>,
    candidate: &Candidate<siros_credential::UsableCredential<'_>>,
    sources: &Sources<'_, '_>,
) -> Result<Shown, PresentationError> {
    Ok(match candidate.answer() {
        Answer::Claims(claims) => Shown::Claims(sources.display.claim_rows(
            candidate.credential().credential(),
            claims.pointers(),
            sources.locales,
        )?),
        Answer::Proof(choice) => {
            let zkp = member
                .answers
                .zkp()
                .ok_or(Inconsistency::ZkpQuery(member.query))?;
            Shown::Proof(verified_rows(zkp.query().query(), zkp.option(choice)?)?)
        }
    })
}
