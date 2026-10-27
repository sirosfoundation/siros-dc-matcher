//! The signing inputs of a chosen offer (A5, A6, A7): one `Sign` effect per signature its
//! presentations need.

use itertools::Itertools;
use rand_core::CryptoRngCore;
use serde_json::Value;
use siros_credential::{Credential, Parsed, UsableCredential};
use siros_dcql::mdoc_components;
use siros_mdoc::{ElementId, Mdoc, SessionTranscript};
use siros_oid4vp::{Presentation, VerifiedRequest};
use siros_sdjwt::{Audience, BeforeEpoch, KbNonce, NumericDate, SdJwt};
use siros_transaction_data::{Amr, Jti, KbJwtInputs, MemberBinding};
use siros_wallet_state::{CredentialId, KeyId};
use siros_zkp_req_nym_auth::presenter::Prepared as NymPrepared;

use super::forms::{DeviceResponse, Form};
use super::selection::Chosen;
use super::sign::{key_id, Sign, SignId, SigningInput};
use crate::error::{Inconsistency, PresentationError};
use siros_dcql::HolderBinding;

use crate::matching::{Answer, Candidate, Claims, ProofChoice};
use crate::plan::{nym_answer, Bound, Offered};
use siros_dcql::QueryId;

/// A chosen offer whose presentations wait for their signatures.
pub struct Prepared<'p, 'a> {
    pub(crate) chosen: Chosen<'p, 'a>,
    pub(crate) members: Vec<PendingMember<'p>>,
    pub(crate) signs: Vec<Sign>,
}

/// A member's presentations, complete or waiting for the signatures of their `Sign` effects.
pub(crate) struct PendingMember<'p> {
    pub(crate) query_id: QueryId,
    pub(crate) credentials: Vec<(CredentialId, Form<'p>)>,
}

/// The audience of a response to `request` (A6): `origin:` and the calling origin over the
/// Digital Credentials API, the Client Identifier with its prefix over redirects, signed
/// requests included (A.4).
///
/// # Errors
///
/// [`PresentationError::AudienceMissing`] for a request without an origin or a Client
/// Identifier.
pub(crate) fn audience(request: &VerifiedRequest) -> Result<Audience, PresentationError> {
    match (request.origin(), request.verifier().client_id()) {
        (Some(origin), _) => Ok(Audience::new(&format!("origin:{origin}"))),
        (None, Some(client_id)) => Ok(Audience::new(client_id.as_str())),
        (None, None) => Err(PresentationError::AudienceMissing),
    }
}

impl<'p, 'a> Chosen<'p, 'a> {
    /// The presentations of the offer and its chosen additions, in that order, one per chosen
    /// credential, and the `Sign` effect of each signature they need (A5).
    ///
    /// - An SD-JWT VC discloses its selected claims (S3). When its query requires holder
    ///   binding, its KB-JWT has `iat` from the plan's time, `nonce`, `aud` (A6) and the claims
    ///   of the transaction entries bound to it (S4, T3), `jti` drawn from `rng`.
    /// - An mdoc discloses its selected elements, and its device key signs over the
    ///   SessionTranscript of the request's `Handover` (A7, M2).
    /// - A nym_auth proof's device key signs the data nym_auth gives for the request's session
    ///   (N2), from a usable attestation and a seed opened again for this use (N3, N4).
    ///
    /// The entries bind to the offer's chosen credentials (T4).
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: a member whose credential names no key pair or holder key, a key
    /// without the factors a transaction requires, a nym_auth credential that no longer passes
    /// its tests, or a presentation its format refuses.
    pub fn prepare(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Prepared<'p, 'a>, PresentationError> {
        let planned = self.planned;
        // The plan's bindings, which the view showed and the digest covers: the chosen members
        // keep every candidate an entry is bound to.
        let bindings = planned
            .transactions
            .bind(&planned.answered, self.offer.members())?;
        let offer = crate::plan::offered(&planned.answered, &self.members)?;
        let added = crate::plan::offered(&planned.answered, &self.added)?;
        let mut signs = Vec::new();
        // The bindings name credentials of the offer's members; the additions' carry none.
        let members = offer
            .iter()
            .chain(added.iter())
            .map(|member| self.pending(member, &bindings, &mut signs, rng))
            .try_collect()?;
        Ok(Prepared {
            chosen: self,
            members,
            signs,
        })
    }

    /// The presentations of `member`'s credentials, with `bindings`' entries, each adding to
    /// `signs` the effect of the signature it needs.
    fn pending(
        &self,
        member: &Offered<'p, 'a>,
        bindings: &[(Bound, MemberBinding<'_, '_>)],
        signs: &mut Vec<Sign>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PendingMember<'p>, PresentationError> {
        let credentials = member
            .candidates
            .iter()
            .map(|&(_, candidate)| {
                let credential: &'p Credential = candidate.credential().credential();
                let id = SignId::new(signs.len());
                let binding = bindings
                    .iter()
                    .find(|(bound, _)| member.carries(bound, candidate))
                    .map(|(_, binding)| binding);
                let form = match candidate.answer() {
                    Answer::Claims(claims) => {
                        let extra = self.transaction_claims(credential, binding, rng)?;
                        self.claims(credential, claims, &extra, id)?
                    }
                    Answer::Proof(choice) => self.proof(member, candidate, choice, id)?,
                };
                if let Form::Unsigned(unsigned, _) = &form {
                    signs.push(Sign::new(id, credential, unsigned.signing_input())?);
                }
                Ok::<_, PresentationError>((credential.entry().credential_id(), form))
            })
            .try_collect()?;
        Ok(PendingMember {
            query_id: member.answers.id().clone(),
            credentials,
        })
    }

    /// The KB-JWT claims of the entries `binding` binds to `credential` (T3), with `jti` drawn
    /// from `rng`; none without entries.
    fn transaction_claims(
        &self,
        credential: &Credential,
        binding: Option<&MemberBinding<'_, '_>>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<(String, Value)>, PresentationError> {
        let Some(binding) = binding else {
            return Ok(Vec::new());
        };
        let mut jti = [0u8; 16];
        rng.fill_bytes(&mut jti);
        let inputs = KbJwtInputs::new(
            Jti::new(jti),
            self.planned.input.request.response_mode(),
            self.amr(&key_id(credential)?)?,
        );
        Ok(binding.kb_jwt_claims(&inputs))
    }

    /// The factors the host reported for the key `kid`.
    fn amr(&self, kid: &KeyId) -> Result<Amr, PresentationError> {
        self.planned
            .input
            .key_factors
            .iter()
            .find(|(key, _)| key == kid)
            .map(|(_, amr)| amr.clone())
            .ok_or_else(|| PresentationError::KeyFactorsMissing(kid.clone()))
    }

    /// The presentation of `claims` of `credential`, the KB-JWT carrying `extra`.
    fn claims(
        &self,
        credential: &'p Credential,
        claims: &Claims,
        extra: &[(String, Value)],
        id: SignId,
    ) -> Result<Form<'p>, PresentationError> {
        match credential.parsed() {
            Parsed::SdJwtVc(sd_jwt) => self.sd_jwt(sd_jwt, claims, extra, id),
            Parsed::Mdoc(mdoc) => self.mdoc(mdoc, claims, id),
        }
    }

    /// The SD-JWT VC's selected disclosures (S3), and its KB-JWT when the query requires holder
    /// binding.
    fn sd_jwt(
        &self,
        sd_jwt: &SdJwt,
        claims: &Claims,
        extra: &[(String, Value)],
        id: SignId,
    ) -> Result<Form<'p>, PresentationError> {
        let presentation = sd_jwt.select(claims.pointers())?;
        if claims.holder_binding() == HolderBinding::Optional {
            return Ok(Form::Ready(Presentation::text(
                presentation.as_str().to_owned(),
            )));
        }
        let input = self.planned.input;
        let iat = NumericDate::of(input.now).map_err(|BeforeEpoch| PresentationError::Time)?;
        let binding = presentation.key_binding(
            iat,
            &audience(input.request)?,
            &KbNonce::new(input.request.nonce().as_str()),
            extra,
        )?;
        Ok(Form::unsigned(binding, id))
    }

    /// The mdoc's selected elements, and the DeviceAuthentication its device key signs over the
    /// SessionTranscript of the request's `Handover` (A7).
    fn mdoc(
        &self,
        mdoc: &'p Mdoc,
        claims: &Claims,
        id: SignId,
    ) -> Result<Form<'p>, PresentationError> {
        let elements: Vec<ElementId> = claims
            .pointers()
            .iter()
            .map(|pointer| {
                let (name_space, identifier) = mdoc_components(pointer)?;
                Ok::<_, PresentationError>(ElementId {
                    name_space,
                    identifier,
                })
            })
            .try_collect()?;
        let disclosure = mdoc.disclose(&elements, Vec::new())?;
        let transcript =
            SessionTranscript::new(self.planned.input.request.handover().session_transcript());
        let input = SigningInput::new(disclosure.signing_input(&transcript).as_bytes().to_vec());
        Ok(Form::unsigned(DeviceResponse { disclosure, input }, id))
    }

    /// The nym_auth statement of `choice` by `candidate`'s credential, admitted as the candidate
    /// carries it, in the request's session.
    fn proof(
        &self,
        member: &Offered<'p, 'a>,
        candidate: &Candidate<UsableCredential<'_>>,
        choice: &ProofChoice,
        id: SignId,
    ) -> Result<Form<'p>, PresentationError> {
        let credential = candidate.credential();
        let nym_auth = self
            .planned
            .nym_auth
            .as_ref()
            .map_err(|refusal| Inconsistency::NymAuthRequest(*refusal))?;
        let zkp = member
            .answers
            .zkp()
            .ok_or(Inconsistency::ZkpQuery(member.query))?;
        let answer = nym_answer(
            credential,
            candidate.admission(),
            zkp,
            choice,
            self.planned.input.now,
        )?;
        let prepared = NymPrepared::new(answer, nym_auth, &key_id(credential.credential())?)?;
        Ok(Form::unsigned(prepared, id))
    }
}
