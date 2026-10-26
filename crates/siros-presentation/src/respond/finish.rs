//! The response of a chosen offer: the signatures parsed against their `Sign` effects (A5), the
//! presentations, one `vp_token` (A8), its submission (P4) and the presentation record (W4).

use rand_core::CryptoRngCore;
use siros_codec::base64url;
use siros_oid4vp::{Presentation, Submission};
use siros_wallet_state::{CredentialId, PresentationId, PresentationRecord, TransactionId};
use siros_zkp_req_nym_auth::prover::NymAuthProver;

use super::prepare::{audience, Form, Prepared, Sign, SignId};
use crate::error::PresentationError;

/// What the wallet sends, and what it records.
pub struct Response {
    submission: Submission,
    record: PresentationRecord,
}

impl Response {
    /// The submission in the form of the request's Response Mode (P4).
    pub fn submission(&self) -> &Submission {
        &self.submission
    }

    /// The record the host appends as a `new_presentation` event (H5).
    pub fn record(&self) -> &PresentationRecord {
        &self.record
    }

    /// The submission and the record.
    pub fn into_parts(self) -> (Submission, PresentationRecord) {
        (self.submission, self.record)
    }
}

impl Prepared<'_, '_> {
    /// The `Sign` effects, each of which the host answers with a signature.
    pub fn signs(&self) -> &[Sign] {
        &self.signs
    }

    /// The response, with `signatures` the host made for [`Prepared::signs`].
    ///
    /// Each signature answers one `Sign` effect and verifies under the key it names, and every
    /// effect has one (A5). `prover` proves
    /// each nym_auth statement in-process, once the device signature verifies under the MSO's
    /// device key. One `vp_token` answers every member, keyed by query id (A8). `rng` gives the
    /// response encryption's ephemeral key and IV, then the record's `presentationId` and
    /// `transactionId`. The record names exactly the instances the presentations use, its
    /// `data` is the `vp_token` as JSON text, its time the plan's, and its `audience` that of
    /// the KB-JWT (A6).
    ///
    /// # Errors
    ///
    /// [`PresentationError`]: a signature missing, repeated, unknown, not 64 bytes or not
    /// verifying, a proof that failed, or a `vp_token` or submission that could not be built.
    pub fn finish(
        self,
        signatures: Vec<(SignId, Vec<u8>)>,
        prover: &dyn NymAuthProver,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Response, PresentationError> {
        let signed = parse(&self.signs, signatures)?;
        let signature = |id: SignId| {
            signed
                .get(id.value())
                .copied()
                .ok_or(PresentationError::SignatureMissing)
        };
        let mut entries: Vec<(String, Vec<Presentation>)> = Vec::new();
        let mut used: Vec<CredentialId> = Vec::new();
        for member in self.members {
            let presentation = match member.form {
                Form::Ready(presentation) => presentation,
                Form::KeyBinding(binding, id) => {
                    Presentation::text(binding.assemble(&signature(id)?))
                }
                Form::Mdoc(disclosure, id) => Presentation::text(base64url::encode(
                    &disclosure.device_response(&signature(id)?),
                )),
                Form::Proof(prepared, id) => {
                    let proof = prepared
                        .prove(&signature(id)?, prover)
                        .map_err(PresentationError::Prove)?;
                    Presentation::cbor_map(proof.encode()).map_err(PresentationError::Response)?
                }
            };
            match entries.iter_mut().find(|(id, _)| id == member.query_id) {
                Some((_, presentations)) => presentations.push(presentation),
                None => entries.push((member.query_id.to_owned(), vec![presentation])),
            }
            if !used.contains(&member.credential) {
                used.push(member.credential);
            }
        }
        let planned = self.chosen.planned;
        let request = planned.input.request;
        let token = request
            .vp_token(entries)
            .map_err(PresentationError::Response)?;
        let submission = token.submission(rng).map_err(PresentationError::Response)?;
        let record = PresentationRecord::new(
            PresentationId::new(rng.next_u64()),
            TransactionId::new(rng.next_u64()),
            token.json().to_string(),
            used,
            planned.input.now,
            audience(request)?,
        );
        Ok(Response { submission, record })
    }
}

/// The signature of each effect of `signs`, by its identifier, verified under the key the
/// effect names (A5).
fn parse(
    signs: &[Sign],
    signatures: Vec<(SignId, Vec<u8>)>,
) -> Result<Vec<[u8; 64]>, PresentationError> {
    let mut by_id: Vec<Option<[u8; 64]>> = vec![None; signs.len()];
    for (id, signature) in signatures {
        let (slot, sign) = by_id
            .get_mut(id.value())
            .zip(signs.get(id.value()))
            .ok_or(PresentationError::SignatureUnknown)?;
        if slot.is_some() {
            return Err(PresentationError::SignatureRepeated);
        }
        *slot = Some(sign.verified(signature)?);
    }
    by_id
        .into_iter()
        .map(|signature| signature.ok_or(PresentationError::SignatureMissing))
        .collect()
}
