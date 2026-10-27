//! Why a request produced no entry, surfaced where it can be seen.
//!
//! This binary has no logging channel: its only imports are `credman` and
//! `credman_v2` to `credman_v7`, none of which exposes anything like a log
//! call, and it runs inside a sandboxed host process that no logcat filter on
//! the wallet side can look into. The picker UI is the one surface it has, so
//! when the wallet registered with its diagnostics shown, each reason a request
//! shows less than it asks for gets one entry naming it.
//!
//! The wallet shows them in its debuggable builds only: an end user cannot act
//! on "unsatisfied", and selecting the entry hands the wallet no pick.
//!
//! Two host behaviours shape this, both learned the hard way and neither
//! documented anywhere:
//!
//! * An entry with no icon is silently dropped. The host logs
//!   `WasmRuntime: Null icon for icon` in its own process and shows nothing.
//!   Every diagnostic therefore carries the wallet's default icon, which the
//!   wallet's writer holds to 64 pixels or more: a 4x4 one was dropped too.
//! * Declaring the same set id twice in one invocation makes the host
//!   discard the *whole* output, silently. Each diagnostic has its own set
//!   id, `siros-debug-<position>`, apart from the offers' `siros-<position>`.

use android_credman::{
    AnyEntry, C8String, C8StringExt, EntrySet, SetEntry, SetSink, Slot, VerificationDisplay,
};
use siros_presentation::OfferIndex;
use siros_registration::{Diagnostics as Shown, Icon, Registration};

/// Why the picker shows less than a request asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unshown {
    /// No entry of the DC API request reads: why, entry by entry.
    Request(String),
    /// A Credential Query makes the request invalid: the refusal's code.
    Refused(&'static str),
    /// The request's transaction data is refused: the refusal's code.
    TransactionData(&'static str),
    /// The queries the transaction data targets have no candidate.
    CredentialUnavailable,
    /// The matching gives no offer: the failure's code.
    Unmatched(&'static str),
    /// The rows of the offer at this position do not show: the error's code.
    Display(OfferIndex, &'static str),
    /// The offer at this position names a query or a candidate the matching lacks.
    Inconsistent(OfferIndex),
    /// The offer at this position has no member.
    Empty(OfferIndex),
}

impl Unshown {
    /// One line for the diagnostic entry's subtitle.
    fn message(&self) -> String {
        match self {
            Self::Request(why) => format!("request: {why}"),
            Self::Refused(code) => format!("refused: {code}"),
            Self::TransactionData(code) => format!("transaction data: {code}"),
            Self::CredentialUnavailable => "transaction data: credential_unavailable".to_owned(),
            Self::Unmatched(code) => format!("no offer: {code}"),
            Self::Display(offer, code) => format!("offer {offer}: {code}"),
            Self::Inconsistent(offer) => format!("offer {offer}: inconsistent"),
            Self::Empty(offer) => format!("offer {offer}: no member"),
        }
    }
}

/// Whether the wallet registered with its diagnostics shown, and the icon they show.
pub(crate) struct Diagnostics<'r> {
    shown: Shown,
    icon: &'r Icon,
}

impl<'r> Diagnostics<'r> {
    /// The diagnostics `registration` asks for.
    pub(crate) fn of(registration: &'r Registration) -> Self {
        Self {
            shown: registration.diagnostics(),
            icon: registration.default_icon(),
        }
    }

    /// Emits one entry per reason of `unshown`, each in its own set, when shown.
    pub(crate) fn emit(&self, sets: &mut impl SetSink, unshown: &[Unshown]) {
        if self.shown == Shown::Hidden {
            return;
        }
        for (at, reason) in unshown.iter().enumerate() {
            let id = C8String::from_str_lossy(&format!("siros-debug-{at}"));
            let cred_id = C8String::from_str_lossy("siros-debug-entry");
            let title = C8String::from_str_lossy("[SIROS DEBUG] no match");
            // Picker subtitles are typically single-line and short. The message is written
            // terse and passed whole, so nothing important silently falls off the end.
            let subtitle = C8String::from_str_lossy(&reason.message());
            let entry = SetEntry::new(
                &cred_id,
                AnyEntry::Verification(VerificationDisplay {
                    icon: self.icon.as_bytes(),
                    title: &title,
                    subtitle: Some(&subtitle),
                    disclaimer: None,
                    warning: None,
                }),
            );
            sets.add_entry_set(&EntrySet::new(&id, Slot::one(&entry), &[]));
        }
    }
}
