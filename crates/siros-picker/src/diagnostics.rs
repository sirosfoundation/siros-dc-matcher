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

use std::io::{Read, Seek};

use android_credman::{
    AnyEntry, C8String, C8StringExt, EntrySet, SetEntry, SetSink, Slot, VerificationDisplay,
};
use siros_presentation::OfferIndex;
use siros_registration::{Diagnostics as Shown, Facts, IconRef, Registration};

/// Why the picker shows less than a request asks for. Its text is one line for the diagnostic
/// entry's subtitle.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Unshown {
    /// No entry of the DC API request reads: why, entry by entry.
    #[error("request: {0}")]
    Request(String),
    /// A Credential Query makes the request invalid: the refusal's code.
    #[error("refused: {0}")]
    Refused(&'static str),
    /// The request's transaction data is refused: the refusal's code.
    #[error("transaction data: {0}")]
    TransactionData(&'static str),
    /// The queries the transaction data targets have no candidate.
    #[error("transaction data: credential_unavailable")]
    CredentialUnavailable,
    /// The matching gives no offer: the failure's code.
    #[error("no offer: {0}")]
    Unmatched(&'static str),
    /// The rows of the matching's offer at this position do not show, which leaves it out:
    /// the error's code.
    #[error("offer {0}: {1}")]
    Display(OfferIndex, &'static str),
    /// A part of the registration the request needs breaks a rule: the error's code.
    #[error("registration: {0}")]
    Registration(&'static str),
}

/// Whether the wallet registered with its diagnostics shown, and the icon they show.
pub(crate) struct Diagnostics {
    shown: Shown,
    icon: IconRef,
}

impl Diagnostics {
    /// The diagnostics a registration of `facts` asks for.
    pub(crate) fn of(facts: &Facts) -> Self {
        Self {
            shown: facts.diagnostics(),
            icon: *facts.default_icon(),
        }
    }

    /// Emits one entry per reason of `unshown`, each in its own set, when shown, with the
    /// wallet's icon read from `registration`. The host drops an entry without an icon: an icon
    /// that does not read leaves nothing to emit.
    pub(crate) fn emit<R: Read + Seek>(
        &self,
        registration: &mut Registration<R>,
        sets: &mut impl SetSink,
        unshown: &[Unshown],
    ) {
        if self.shown == Shown::Hidden || unshown.is_empty() {
            return;
        }
        let Ok(icon) = registration.icon(self.icon) else {
            return;
        };
        for (at, reason) in unshown.iter().enumerate() {
            let id = C8String::from_str_lossy(&format!("siros-debug-{at}"));
            let cred_id = C8String::from_str_lossy("siros-debug-entry");
            let title = C8String::from_str_lossy("[SIROS DEBUG] no match");
            // Picker subtitles are typically single-line and short. The message is written
            // terse and passed whole, so nothing important silently falls off the end.
            let subtitle = C8String::from_str_lossy(&reason.to_string());
            let entry = SetEntry::new(
                &cred_id,
                AnyEntry::Verification(VerificationDisplay {
                    icon: icon.as_bytes(),
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
