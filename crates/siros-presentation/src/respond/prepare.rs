//! The signing inputs of a chosen offer (A5, A6, A7): one `Sign` effect per signature its
//! presentations need.

use rand_core::CryptoRngCore;
use siros_credential::{Parsed, UsableCredential};
use siros_dcql::mdoc_components;
use siros_mdoc::{Disclosure, ElementId};
use siros_oid4vp::{Presentation, VerifiedRequest};
use siros_sdjwt::KeyBinding;
use siros_transaction_data::{Jti, KbJwtInputs};
use siros_wallet_state::{CredentialId, KeyId};
use siros_zkp_req_nym_auth::presenter::Prepared as NymPrepared;

use super::selection::Chosen;
use crate::error::PresentationError;
use crate::matching::{Answer, Claims, ProofChoice};
use crate::offers::Member;
use crate::plan::nym_answer;

/// The identifier of a [`Sign`] effect, which its signature names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignId(usize);

impl SignId {
    /// The identifier `id`, as the host returns it.
    pub fn new(id: usize) -> Self {
        Self(id)
    }

    /// The number.
    pub fn value(self) -> usize {
        self.0
    }
}

/// An ES256 signature the host makes (H3): of exactly [`Sign::input`], with the key pair
/// [`Sign::key`], returned as `r ‖ s`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign {
    id: SignId,
    key: KeyId,
    input: Vec<u8>,
}

impl Sign {
    /// The identifier the signature names.
    pub fn id(&self) -> SignId {
        self.id
    }

    /// The key pair that signs.
    pub fn key(&self) -> &KeyId {
        &self.key
    }

    /// The bytes it signs.
    pub fn input(&self) -> &[u8] {
        &self.input
    }
}

/// A chosen offer whose presentations wait for their signatures.
pub struct Prepared<'p, 'a> {
    pub(crate) chosen: Chosen<'p, 'a>,
    pub(crate) members: Vec<Pending<'p>>,
    pub(crate) signs: Vec<Sign>,
}

/// A member's presentation, complete or waiting for the signature of its `Sign` effect.
pub(crate) struct Pending<'p> {
    pub(crate) query_id: &'p str,
    pub(crate) credential: CredentialId,
    pub(crate) form: Form<'p>,
}

pub(crate) enum Form<'p> {
    /// An SD-JWT VC without key binding.
    Ready(Presentation),
    /// An SD-JWT VC with its KB-JWT.
    KeyBinding(KeyBinding, SignId),
    /// An mdoc's `DeviceResponse`.
    Mdoc(Disclosure<'p>, SignId),
    /// A nym_auth proof, whose device signature the prover's job needs.
    Proof(Box<NymPrepared>, SignId),
}

impl<'p, 'a> Chosen<'p, 'a> {
    /// The presentations of the offer and its chosen additions, in that order, and the `Sign`
    /// effect of each signature they need (A5).
    ///
    /// - An SD-JWT VC discloses its selected claims (S3). When its query requires holder
    ///   binding, its KB-JWT has `iat` from the plan's time, `nonce`, `aud` (A6) and the claims
    ///   of the transaction entries bound to it (S4, T3), `jti` drawn from `rng`.
    /// - An mdoc discloses its selected elements, and its device key signs over the
    ///   SessionTranscript of the request's `Handover` (A7, M2).
    /// - A nym_auth proof's device key signs the data nym_auth gives for the request's session
    ///   (N2), from a usable attestation and a seed opened again for this use (N3, N4).
    ///
    /// `aud` is the Client Identifier with its prefix over redirects, and `origin:` with the
    /// calling origin over the Digital Credentials API, signed requests included (A.4).
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: a member whose credential names no key pair, a key without the
    /// factors a transaction requires, or a presentation its format refuses.
    pub fn prepare(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Prepared<'p, 'a>, PresentationError> {
        let mut members = Vec::new();
        let mut signs = Vec::new();
        // The offer's members by their position, to which entries bind, then the additions'.
        let chosen: Vec<(Option<usize>, &Member)> = self
            .offer
            .members()
            .iter()
            .enumerate()
            .map(|(at, member)| (Some(at), member))
            .chain(
                self.additions
                    .iter()
                    .flat_map(|a| a.members().iter().map(|member| (None, member))),
            )
            .collect();
        let bindings = self
            .planned
            .transactions
            .bind(&self.planned.answered, self.offer.members())
            .map_err(PresentationError::TransactionData)?;
        for (at, member) in chosen {
            let answers = self
                .planned
                .answered
                .queries()
                .get(member.query())
                .ok_or(PresentationError::AnswerMismatch)?;
            let candidate = answers
                .candidates()
                .get(member.candidate())
                .ok_or(PresentationError::AnswerMismatch)?;
            let credential: &'p UsableCredential<'a> = candidate.credential();
            let id = SignId(signs.len());
            let key = || {
                credential
                    .credential()
                    .key_id()
                    .cloned()
                    .ok_or(PresentationError::KeyMissing)
            };
            let form = match candidate.answer() {
                Answer::Claims(claims) => {
                    let extra = match bindings.iter().find(|(bound, _)| Some(*bound) == at) {
                        None => Vec::new(),
                        Some((_, binding)) => {
                            let kid = key()?;
                            let mut jti = [0u8; 16];
                            rng.fill_bytes(&mut jti);
                            let inputs = KbJwtInputs::new(
                                Jti::new(jti),
                                self.planned.input.request.response_mode(),
                                self.amr(&kid)?,
                            );
                            binding.kb_jwt_claims(&inputs)
                        }
                    };
                    self.claims(credential, claims, &extra, id)?
                }
                Answer::Proof(choice) => {
                    let zkp = answers.zkp().ok_or(PresentationError::AnswerMismatch)?;
                    self.proof(credential, zkp, choice, id)?
                }
            };
            let input = match &form {
                Form::Ready(_) => None,
                Form::KeyBinding(kb, _) => Some(kb.signing_input().to_vec()),
                Form::Mdoc(disclosure, _) => Some(
                    disclosure
                        .signing_input(&self.planned.input.request.handover().session_transcript()),
                ),
                Form::Proof(prepared, _) => Some(prepared.data_to_sign().to_vec()),
            };
            if let Some(input) = input {
                signs.push(Sign {
                    id,
                    key: key()?,
                    input,
                });
            }
            members.push(Pending {
                query_id: &answers.query().id,
                credential: credential.credential().entry().credential_id(),
                form,
            });
        }
        Ok(Prepared {
            chosen: self,
            members,
            signs,
        })
    }

    /// The factors the host reported for the key `kid`.
    fn amr(&self, kid: &KeyId) -> Result<siros_transaction_data::Amr, PresentationError> {
        self.planned
            .input
            .key_factors
            .iter()
            .find(|(key, _)| key == kid)
            .map(|(_, amr)| amr.clone())
            .ok_or(PresentationError::KeyFactorsMissing)
    }

    fn claims(
        &self,
        credential: &'p UsableCredential<'a>,
        claims: &Claims,
        extra: &[(String, serde_json::Value)],
        id: SignId,
    ) -> Result<Form<'p>, PresentationError> {
        let request = self.planned.input.request;
        match credential.credential().parsed() {
            Parsed::SdJwtVc(sd_jwt) => {
                let presentation = sd_jwt
                    .select(claims.pointers())
                    .map_err(PresentationError::Pointer)?;
                if !claims.holder_binding() {
                    return Ok(Form::Ready(Presentation::text(
                        presentation.as_str().to_owned(),
                    )));
                }
                let iat = u64::try_from(self.planned.input.now.unix())
                    .map_err(|_| PresentationError::Time)?;
                let binding = presentation
                    .key_binding(iat, &audience(request)?, request.nonce(), extra)
                    .map_err(PresentationError::KeyBinding)?;
                Ok(Form::KeyBinding(binding, id))
            }
            Parsed::Mdoc(mdoc) => {
                let elements = claims
                    .pointers()
                    .iter()
                    .map(|pointer| {
                        let (name_space, identifier) = mdoc_components(pointer.components())
                            .map_err(PresentationError::Pointer)?;
                        Ok(ElementId {
                            name_space,
                            identifier,
                        })
                    })
                    .collect::<Result<Vec<_>, PresentationError>>()?;
                let disclosure = mdoc
                    .disclose(&elements, Vec::new())
                    .map_err(PresentationError::Disclosure)?;
                Ok(Form::Mdoc(disclosure, id))
            }
        }
    }

    fn proof(
        &self,
        credential: &UsableCredential<'_>,
        zkp: &crate::matching::ZkpQuery,
        choice: &ProofChoice,
        id: SignId,
    ) -> Result<Form<'p>, PresentationError> {
        let nym_auth = self
            .planned
            .nym_auth
            .as_ref()
            .ok_or(PresentationError::AnswerMismatch)?;
        let answer = nym_answer(credential, zkp, choice, self.planned.input.now)
            .ok_or(PresentationError::AnswerMismatch)?;
        let kid = credential
            .credential()
            .key_id()
            .ok_or(PresentationError::KeyMissing)?;
        let prepared =
            NymPrepared::new(answer, nym_auth, kid.as_str()).map_err(PresentationError::Prove)?;
        Ok(Form::Proof(Box::new(prepared), id))
    }
}

/// The audience of the response (A6): `origin:` and the calling origin over the Digital
/// Credentials API, the Client Identifier with its prefix over redirects.
pub(crate) fn audience(request: &VerifiedRequest) -> Result<String, PresentationError> {
    match (request.origin(), request.verifier().client_id()) {
        (Some(origin), _) => Ok(format!("origin:{origin}")),
        (None, Some(client_id)) => Ok(client_id.as_str().to_owned()),
        (None, None) => Err(PresentationError::AudienceMissing),
    }
}
