//! What an offer shows (A3, T4): each credential of its members with its claim or proof
//! statement fields and the transaction entry bound to it, after its additions' rows show.

use siros_dcql::QueryId;
use siros_display::Field;
use siros_presentation::{Answer, Answered, Answers, Candidate, Offer, OfferIndex, Transactions};
use siros_registration::RegisteredCredential;
use siros_transaction_data::Deferral;

use crate::diagnostics::Unshown;
use crate::fields::TransactionShown;
use crate::matching::NoChoice;

/// The matching an offer shows from.
pub(crate) struct Matched<'a, 'r> {
    pub(crate) answered: &'a Answered<'r, &'a RegisteredCredential, NoChoice>,
    pub(crate) transactions: &'a Transactions<Deferral>,
}

/// One credential of an offer as its entry shows it.
pub(crate) struct Presented<'a> {
    pub(crate) credential: &'a RegisteredCredential,
    pub(crate) query: QueryId,
    pub(crate) fields: Vec<Field>,
    pub(crate) transaction: TransactionShown,
}

impl<'a> Matched<'a, '_> {
    /// Each candidate of each member of `offer`, the matching's offer at `index`, as its entry
    /// shows it, with the transaction entry bound to it (T4).
    ///
    /// # Errors
    ///
    /// [`Unshown::Display`] when the claims or proof statements of a member or of an addition
    /// do not show: the wallet's plan leaves the offer out alike, and the other offers stay.
    ///
    /// # Panics
    ///
    /// When `offer` breaks the presentation component's guarantee: its members and additions
    /// name queries and candidates of the matching it was built from.
    pub(crate) fn shown(
        &self,
        index: OfferIndex,
        offer: &Offer,
    ) -> Result<Vec<Presented<'a>>, Unshown> {
        let bindings = self.transactions.bind(self.answered, offer.members());
        let mut presented = Vec::new();
        for member in offer.members() {
            let (answers, candidates) = self.candidates(member);
            for candidate in candidates {
                let credential: &'a RegisteredCredential = candidate.credential();
                let transaction = match bindings.iter().find(|b| b.binds(answers, candidate)) {
                    Some(binding) => TransactionShown::of(binding.taken())
                        .map_err(|error| Unshown::Display(index, error.code()))?,
                    None => TransactionShown::Nothing,
                };
                presented.push(Presented {
                    credential,
                    query: answers.id().clone(),
                    fields: fields(index, answers, credential, candidate.answer())?,
                    transaction,
                });
            }
        }
        for member in offer
            .additions()
            .iter()
            .flat_map(|addition| addition.members())
        {
            let (answers, candidates) = self.candidates(member);
            for candidate in candidates {
                fields(index, answers, candidate.credential(), candidate.answer()).map(drop)?;
            }
        }
        Ok(presented)
    }

    /// The answers of `member`'s query and its candidates.
    ///
    /// # Panics
    ///
    /// When `member` names a query or a candidate the matching lacks.
    #[expect(
        clippy::expect_used,
        reason = "a member that names what its matching lacks is a bug of the presentation \
                  component, and no entry the picker could emit for it is right"
    )]
    fn candidates(
        &self,
        member: &siros_presentation::Member,
    ) -> (
        &'a Answers<'a, &'a RegisteredCredential, NoChoice>,
        Vec<&'a Candidate<&'a RegisteredCredential>>,
    ) {
        // The presentation component's guarantee: an offer's members name queries and
        // candidates of the matching it was built from.
        let answers = self
            .answered
            .answers(member.query())
            .expect("an offer's query is a query of its matching");
        let candidates = member
            .candidates()
            .iter()
            .map(|&candidate| {
                answers
                    .candidate(candidate)
                    .expect("an offer's candidate is a candidate of its query")
            })
            .collect();
        (answers, candidates)
    }
}

/// The fields of what `credential` answers for `answers`: the rows of the claims it discloses,
/// or the proof statement rows of the `zkp_req` option it answers.
///
/// # Errors
///
/// [`Unshown::Display`] for claims or statements that do not show.
///
/// # Panics
///
/// When a proof answer's query has no `zkp_req` query or no option of its choice.
#[expect(
    clippy::expect_used,
    reason = "a proof answer without its query's `zkp_req` option is a bug of the presentation \
              component, and no proof rows the picker could show for it are right"
)]
fn fields(
    index: OfferIndex,
    answers: &Answers<'_, &RegisteredCredential, NoChoice>,
    credential: &RegisteredCredential,
    answer: &Answer,
) -> Result<Vec<Field>, Unshown> {
    match answer {
        Answer::Claims(claims) => credential
            .labels()
            .rows(credential.claims(), claims.pointers())
            .map(|rows| rows.iter().map(Field::of_claim).collect())
            .map_err(|error| Unshown::Display(index, error.code())),
        Answer::Proof(choice) => {
            // The presentation component's guarantee: a proof answer belongs to a `zkp_req`
            // query, and its choice is an option of that query.
            let zkp = answers
                .zkp()
                .expect("a proof answer's query is a zkp_req query");
            let option = zkp.option(choice);
            siros_display::proof::rows(zkp.query().query(), option)
                .map_err(|error| Unshown::Display(index, error.code()))
        }
    }
}
