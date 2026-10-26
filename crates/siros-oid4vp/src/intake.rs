//! Request intake (P1): from a redirect authorization request URI, or a DC API request and
//! its calling origin, to a [`VerifiedRequest`], sans-IO.
//!
//! The host carries an [`IntakeState`]: the inputs and every effect result so far. Each
//! [`IntakeState::step`] runs intake again from the inputs, checks every rule again, and
//! answers each effect it reaches from the results in order. The first effect without a
//! result is returned for the host to perform; when none remains, the request is verified.
//! Intake is deterministic, so the same state gives the same outcome on any host.

mod attestation;
mod dc_api;
mod error;
mod redirect;
mod request;
mod signature;
mod trust;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use siros_codec::base64url;

pub use error::{IntakeError, VerifierInfoRule};
pub use trust::{KeyMaterial, Trust, TrustAnswer, TrustSubject};

use crate::fetch::{Fetch, FetchResponse};
use crate::response::Submission;
use crate::verified::VerifiedRequest;

/// An effect intake asks the host to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Fetch the Request Object from `request_uri`.
    Fetch(Fetch),
    /// Evaluate trust in the verifier.
    Trust(Trust),
}

/// The host's result of an [`Effect`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectResult {
    /// The response to an [`Effect::Fetch`].
    Fetched(FetchResponse),
    /// The answer to an [`Effect::Trust`].
    Trusted(TrustAnswer),
}

/// What a step of intake gives.
#[derive(Debug)]
pub enum Step {
    /// An effect for the host; its result goes to [`IntakeState::answer`].
    Effect(Effect),
    /// The verified request.
    Verified(Box<VerifiedRequest>),
}

/// Intake so far: its inputs and the effect results in the order intake asked for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntakeState {
    start: Start,
    now_unix: u64,
    answers: Vec<EffectResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Start {
    /// An authorization request URI from a link or a QR code.
    Redirect {
        uri: String,
        vp_formats_supported: Map<String, Value>,
        wallet_nonce: String,
    },
    /// A DC API request and the origin the platform attests.
    DcApi { request: Vec<u8>, origin: String },
}

impl IntakeState {
    /// Intake of an authorization request URI (Section 5).
    ///
    /// `vp_formats_supported` is the wallet's, for the `wallet_metadata` of a
    /// `request_uri_method=post` fetch (Section 5.10); `rng` draws its `wallet_nonce`.
    /// `now_unix` is the host's time in seconds since the Unix epoch, against which a Verifier
    /// Attestation JWT's validity is judged.
    pub fn redirect(
        uri: &str,
        vp_formats_supported: Map<String, Value>,
        now_unix: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        Self {
            start: Start::Redirect {
                uri: uri.to_owned(),
                vp_formats_supported,
                wallet_nonce: base64url::encode(&nonce).into_string(),
            },
            now_unix,
            answers: Vec::new(),
        }
    }

    /// Intake of a DC API request `{"requests": [{"protocol", "data"}, …]}` (Appendix A) that
    /// the platform received from `origin`.
    ///
    /// The entry is the one the credential picker reads: the first whose protocol is one of
    /// A.1 and whose data has that protocol's shape (`crate::UnverifiedRequest`).
    #[must_use]
    pub fn dc_api(request: &[u8], origin: &str, now_unix: u64) -> Self {
        Self {
            start: Start::DcApi {
                request: request.to_vec(),
                origin: origin.to_owned(),
            },
            now_unix,
            answers: Vec::new(),
        }
    }

    /// Records the result of the effect the last [`Self::step`] returned.
    pub fn answer(&mut self, result: EffectResult) {
        self.answers.push(result);
    }

    /// Runs intake from the inputs and the results so far.
    ///
    /// # Errors
    ///
    /// [`IntakeError`]: the first rule the request breaks, or a result that does not answer
    /// the effect it stands for.
    pub fn step(&self) -> Result<Step, IntakeError> {
        let mut answers = Answers {
            rest: self.answers.iter(),
        };
        let outcome = match &self.start {
            Start::Redirect {
                uri,
                vp_formats_supported,
                wallet_nonce,
            } => {
                let wallet = redirect::Wallet {
                    vp_formats_supported,
                    nonce: wallet_nonce,
                };
                redirect::intake(uri, &wallet, self.now_unix, &mut answers)
            }
            Start::DcApi { request, origin } => {
                dc_api::intake(request, origin, self.now_unix, &mut answers)
            }
        };
        match outcome {
            Ok(_) if answers.rest.next().is_some() => Err(IntakeError::UnusedAnswer),
            Ok(verified) => Ok(Step::Verified(Box::new(verified))),
            Err(Halt::Pending(effect)) => Ok(Step::Effect(effect)),
            Err(Halt::Failed(error) | Halt::HostFault(error)) => Err(error),
        }
    }

    /// The error submission for a refusal of this request, when its response target is
    /// verified (P5).
    ///
    /// Over the DC API the platform returns the response to the origin it attests, so a
    /// refusal is `{"error": …}` (A.2, A.4). Over redirects no target is verified before
    /// intake succeeds, and the answer is `None`.
    #[must_use]
    pub fn error_submission(&self, error: IntakeError) -> Option<Submission> {
        match self.start {
            Start::DcApi { .. } => Some(Submission::dc_api_error(error.error_code())),
            Start::Redirect { .. } => None,
        }
    }
}

/// Why a run of intake stopped before the verified request.
pub(crate) enum Halt {
    /// The effect has no result yet.
    Pending(Effect),
    /// The request breaks a rule.
    Failed(IntakeError),
    /// A result does not fit its effect.
    HostFault(IntakeError),
}

impl From<IntakeError> for Halt {
    fn from(error: IntakeError) -> Self {
        Self::Failed(error)
    }
}

impl From<crate::client_id::ClientIdError> for Halt {
    fn from(error: crate::client_id::ClientIdError) -> Self {
        Self::Failed(IntakeError::ClientId(error))
    }
}

/// The results not yet used by this run.
pub(crate) struct Answers<'a> {
    rest: std::slice::Iter<'a, EffectResult>,
}

impl<'a> Answers<'a> {
    fn fetch(&mut self, fetch: Fetch) -> Result<&'a FetchResponse, Halt> {
        match self.rest.next() {
            None => Err(Halt::Pending(Effect::Fetch(fetch))),
            Some(EffectResult::Fetched(response)) => Ok(response),
            Some(EffectResult::Trusted(_)) => Err(Halt::HostFault(IntakeError::AnswerMismatch)),
        }
    }

    fn trust(&mut self, trust: Trust) -> Result<&'a TrustAnswer, Halt> {
        match self.rest.next() {
            None => Err(Halt::Pending(Effect::Trust(trust))),
            Some(EffectResult::Trusted(answer)) => Ok(answer),
            Some(EffectResult::Fetched(_)) => Err(Halt::HostFault(IntakeError::AnswerMismatch)),
        }
    }
}
