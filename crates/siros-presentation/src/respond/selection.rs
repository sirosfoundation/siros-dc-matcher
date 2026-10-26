//! The user's selection, parsed against the plan (A4), and the refusal of a background
//! fulfilment that needs the wallet's display (A9).

use siros_codec::base64url;

use crate::display_rule::WalletDisplay;
use crate::error::PresentationError;
use crate::offers::{Addition, Offer};
use crate::plan::Planned;

/// The user's choice in a consent view, as the UI returns it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selection {
    digest: [u8; 32],
    offer: usize,
    additions: Vec<usize>,
}

impl Selection {
    /// The choice of the offer at `offer` and of its additions at `additions`, in the view
    /// whose [`ConsentView::digest`](crate::ConsentView::digest) is `digest`.
    ///
    /// # Errors
    ///
    /// [`PresentationError::DigestMalformed`] when `digest` is not 32 bytes of unpadded
    /// base64url.
    pub fn new(
        digest: &str,
        offer: usize,
        additions: Vec<usize>,
    ) -> Result<Self, PresentationError> {
        let digest = base64url::decode(digest)
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or(PresentationError::DigestMalformed)?;
        Ok(Self {
            digest,
            offer,
            additions,
        })
    }
}

/// How the wallet fulfils a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fulfilment {
    /// On its own UI, where the user consented.
    WalletUi,
    /// From its background service, after the user consented on the picker's display.
    Background,
}

/// An offer and additions of a plan that the user chose.
pub struct Chosen<'p, 'a> {
    pub(crate) planned: &'p Planned<'a>,
    pub(crate) offer: &'p Offer,
    pub(crate) additions: Vec<&'p Addition>,
}

impl<'a> Planned<'a> {
    /// The offer `selection` chose in this plan, fulfilled as `fulfilment` says.
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: the digest of another plan, an unknown offer or addition, an
    /// addition chosen twice or answering a query another chosen addition answers, or a
    /// background fulfilment of an offer that needs the wallet's display.
    pub fn choose(
        &self,
        selection: &Selection,
        fulfilment: Fulfilment,
    ) -> Result<Chosen<'_, 'a>, PresentationError> {
        if selection.digest != self.digest {
            return Err(PresentationError::DigestMismatch);
        }
        let offer = self
            .offers
            .offers()
            .get(selection.offer)
            .ok_or(PresentationError::OfferUnknown)?;
        let view = self
            .view
            .offers()
            .get(selection.offer)
            .ok_or(PresentationError::OfferUnknown)?;
        let mut additions: Vec<&Addition> = Vec::with_capacity(selection.additions.len());
        for &index in &selection.additions {
            let addition = offer
                .additions()
                .get(index)
                .ok_or(PresentationError::AdditionUnknown)?;
            let conflicts = additions.iter().any(|chosen| {
                chosen
                    .members()
                    .iter()
                    .any(|a| addition.members().iter().any(|b| a.query() == b.query()))
            });
            if conflicts {
                return Err(PresentationError::AdditionConflict);
            }
            additions.push(addition);
        }
        if fulfilment == Fulfilment::Background && view.wallet_display() == WalletDisplay::Needed {
            return Err(PresentationError::WalletDisplayNeeded);
        }
        Ok(Chosen {
            planned: self,
            offer,
            additions,
        })
    }
}
