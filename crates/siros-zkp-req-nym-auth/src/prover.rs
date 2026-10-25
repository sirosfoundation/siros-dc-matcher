//! The interface to the provers. A host implements it with a system's prover and verifier,
//! such as those of zk-cred-longfellow and zk-cred-vega; this crate holds no prover.
//!
//! Both sides build the same [`Statement`] (system rulebooks, Section 4): the Wallet from the
//! credential and the session, the Verifier from its own request, session, clock and trust
//! configuration and from the prover-supplied values of the presentation.

use zeroize::Zeroizing;

use crate::date::{Date, DateTime};
use crate::mdoc::P256Key;
use crate::system::NymAuthSystem;

/// The public values of a nym_auth mdoc proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The system.
    pub system: NymAuthSystem,
    /// The proof backend.
    pub proof_backend: String,
    /// The `docType` the circuits check, `eu.europa.ec.eudi.nym_auth.1`.
    pub doc_type: &'static str,
    /// `inputs.issuer_key_set[0]`: the Document Signer certificate, DER.
    pub issuer_certificate: Vec<u8>,
    /// The issuer key Q of that certificate.
    pub issuer_key: P256Key,
    /// T: `inputs.proof_time`.
    pub proof_time: DateTime,
    /// E, the earliest birth date; `None` for the system's widest value.
    pub earliest: Option<Date>,
    /// C, the latest birth date; `None` for the system's widest value.
    pub cutoff: Option<Date>,
    /// `verifier_input` of the `pseudonym` item.
    pub verifier_input: [u8; 32],
    /// The encoded `SessionTranscript`, which seeds Longfellow's transcript.
    pub session_transcript: Vec<u8>,
    /// e2: the SHA-256 of the message the device key signed.
    pub challenge_digest: [u8; 32],
}

/// What a prover needs to prove a [`Statement`] (system rulebooks, Section 7).
pub struct ProofJob {
    /// The public values.
    pub statement: Statement,
    /// The credential's `IssuerSigned`, as issued.
    pub issuer_signed: Vec<u8>,
    /// The 16-byte `secret_seed`. Zeroed when the job is dropped.
    pub secret_seed: Zeroizing<[u8; 16]>,
    /// The device key's ES256 signature on the data to sign, `r ‖ s`. It verifies under the
    /// MSO's device key.
    pub device_signature: [u8; 64],
}

impl std::fmt::Debug for ProofJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProofJob")
            .field("statement", &self.statement)
            .finish_non_exhaustive()
    }
}

/// What a prover returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofOutput {
    /// `zk_proof`, as the proof backend specification defines it.
    pub zk_proof: Vec<u8>,
    /// The pseudonym the proof establishes. It must equal the catalogue's value.
    pub pseudonym: [u8; 32],
}

/// Why a prover made no proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProverFailure {
    /// The credential lies outside the form the system reads (Section 2): `credential_form`.
    CredentialForm,
    /// The User or the host cancelled.
    Cancelled,
    /// The system's artifacts or prover are not available here.
    Unavailable,
    /// Proving failed.
    Failed,
}

/// A system's prover.
pub trait NymAuthProver {
    /// Proves `job.statement`.
    ///
    /// # Errors
    ///
    /// [`ProverFailure`]: why no proof was made.
    fn prove(&self, job: &ProofJob) -> Result<ProofOutput, ProverFailure>;
}

/// Why a verifier refused a proof (system rulebooks, Section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProofFailure {
    /// `zk_proof` breaks the format of the proof backend: `proof_encoding`.
    Encoding,
    /// A circuit's proof fails: `proof_invalid`.
    Invalid,
    /// The proof's public values differ from the statement: `public_input`.
    PublicInput,
}

/// A system's verifier.
pub trait NymAuthProofVerifier {
    /// Verifies `zk_proof` against `statement` and the pseudonym of `results`.
    ///
    /// # Errors
    ///
    /// [`ProofFailure`]: why the proof is refused.
    fn verify(
        &self,
        statement: &Statement,
        pseudonym: &[u8; 32],
        zk_proof: &[u8],
    ) -> Result<(), ProofFailure>;
}
