//! The `verifier_attestation` prefix: a Verifier Attestation JWT in the `jwt` Header Parameter
//! binds the Client Identifier to the key that signs the request (OpenID4VP 1.0, Sections
//! 5.9.3 and 12).

use serde_json::{Map, Value};

use super::signature::{by_request, strings, UriRule, Verifier};
use super::trust::{self, KeyMaterial, TrustSubject};
use super::{Answers, Halt, IntakeError};
use crate::client_id::ClientId;
use crate::jose::{self, Signed};
use crate::x509::Chain;

/// The `typ` of a Verifier Attestation JWT (Section 12).
const ATTESTATION_TYP: &str = "verifier-attestation+jwt";

/// Authenticates a request of a `verifier_attestation` client.
///
/// The attestation's `sub` is the Client Identifier, it is valid at `now_unix`, its `cnf` key
/// signs the request, and its issuer's key signs the attestation: the leaf of the
/// attestation's `x5c`, or the key the host resolves for the issuer. The host's verdict on
/// the issuer is the verdict on the Verifier.
pub(super) fn authenticate(
    signed: &Signed,
    client_id: ClientId,
    now_unix: u64,
    answers: &mut Answers<'_>,
) -> Result<Verifier, Halt> {
    let jwt = signed.text("jwt").ok_or(IntakeError::AttestationInvalid)?;
    let (attestation, payload) = jose::compact(jwt).map_err(|_| IntakeError::AttestationInvalid)?;
    if attestation.text("typ") != Some(ATTESTATION_TYP) {
        return Err(IntakeError::AttestationInvalid.into());
    }
    let claims = Claims::parse(&payload).ok_or(IntakeError::AttestationInvalid)?;
    if claims.sub != client_id.value() {
        return Err(IntakeError::AttestationSubjectMismatch.into());
    }
    // RFC 7519, Sections 4.1.4 and 4.1.5. NumericDate may be fractional.
    let now = now_unix as f64;
    if now >= claims.exp || claims.nbf.is_some_and(|nbf| now < nbf) {
        return Err(IntakeError::AttestationExpired.into());
    }
    signed.verify(&claims.cnf)?;
    let issuer = TrustSubject::AttestationIssuer(claims.iss);
    let trusted = match attestation.header().get("x5c") {
        Some(x5c) => {
            let chain = Chain::parse(Some(x5c))?;
            attestation
                .verify(chain.key())
                .map_err(|_| IntakeError::AttestationSignatureInvalid)?;
            trust::verdict(answers, issuer, KeyMaterial::X509Chain(chain.into_der()))?
        }
        None => {
            let kid = attestation.text("kid").map(str::to_owned);
            let resolved = trust::resolve(answers, issuer, kid, None, false)?;
            attestation
                .verify(&resolved.key)
                .map_err(|_| IntakeError::AttestationSignatureInvalid)?;
            resolved.trusted
        }
    };
    let response_uri = claims.redirect_uris.map_or(UriRule::Any, UriRule::OneOf);
    Ok(by_request(client_id, trusted, response_uri))
}

/// The claims of a Verifier Attestation JWT this wallet reads (Section 12).
struct Claims {
    iss: String,
    sub: String,
    exp: f64,
    nbf: Option<f64>,
    cnf: p256::PublicKey,
    redirect_uris: Option<Vec<String>>,
}

impl Claims {
    fn parse(payload: &[u8]) -> Option<Self> {
        let claims: Map<String, Value> = serde_json::from_slice(payload).ok()?;
        let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
        let nbf = match claims.get("nbf") {
            None => None,
            Some(nbf) => Some(nbf.as_f64()?),
        };
        let redirect_uris = match claims.get("redirect_uris") {
            None => None,
            Some(uris) => Some(strings(uris)?),
        };
        Some(Self {
            iss: text("iss")?,
            sub: text("sub")?,
            exp: claims.get("exp")?.as_f64()?,
            nbf,
            cnf: jose::p256_key(claims.get("cnf")?.get("jwk")?)?,
            redirect_uris,
        })
    }
}
