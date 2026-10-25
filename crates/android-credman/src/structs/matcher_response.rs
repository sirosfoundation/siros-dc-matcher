use crate::{CredentialEntry, CredentialSet, CredmanApply, CredmanContext, InlineIssuanceEntry};
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub enum MatcherResult<'a> {
    Single(CredentialEntry<'a>),
    Group(CredentialSet<'a>),
    InlineIssuance(InlineIssuanceEntry<'a>),
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for MatcherResult<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        match self {
            MatcherResult::Single(entry) => CredmanApply::apply(entry, ctx),
            MatcherResult::Group(set) => CredmanApply::apply(set, ctx),
            MatcherResult::InlineIssuance(entry) => CredmanApply::apply(entry, ctx),
        }
    }
}

/// A collection of results to be returned by the Matcher.
///
/// This allows mixing multiple standalone entries and multiple sets.
#[derive(Debug, Clone, Default)]
pub struct MatcherResponse<'a> {
    pub results: Cow<'a, [MatcherResult<'a>]>,
}

impl<'a> MatcherResponse<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_result(mut self, result: MatcherResult<'a>) -> Self {
        let mut results = self.results.into_owned();
        results.push(result);
        self.results = Cow::Owned(results);
        self
    }

    pub fn add_results<I>(mut self, results: I) -> Self
    where
        I: IntoIterator<Item = MatcherResult<'a>>,
    {
        let mut out = self.results.into_owned();
        out.extend(results);
        self.results = Cow::Owned(out);
        self
    }

    pub fn add_single(self, entry: CredentialEntry<'a>) -> Self {
        self.add_result(MatcherResult::Single(entry))
    }

    pub fn add_singles<I>(self, entries: I) -> Self
    where
        I: IntoIterator<Item = CredentialEntry<'a>>,
    {
        self.add_results(entries.into_iter().map(MatcherResult::Single))
    }

    pub fn add_group(self, set: CredentialSet<'a>) -> Self {
        self.add_result(MatcherResult::Group(set))
    }

    pub fn add_inline_issuance(self, entry: InlineIssuanceEntry<'a>) -> Self {
        self.add_result(MatcherResult::InlineIssuance(entry))
    }

    pub fn add_inline_issuances<I>(self, entries: I) -> Self
    where
        I: IntoIterator<Item = InlineIssuanceEntry<'a>>,
    {
        self.add_results(entries.into_iter().map(MatcherResult::InlineIssuance))
    }

    pub fn add_groups<I>(self, sets: I) -> Self
    where
        I: IntoIterator<Item = CredentialSet<'a>>,
    {
        self.add_results(sets.into_iter().map(MatcherResult::Group))
    }
}

impl<'a, 'b> CredmanApply<CredmanContext<'b>> for MatcherResponse<'a> {
    fn apply(&self, ctx: CredmanContext<'b>) {
        for result in self.results.iter() {
            CredmanApply::apply(result, ctx);
        }
    }
}
