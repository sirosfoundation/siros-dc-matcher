//! The `verifier_attestation` prefix: a Verifier Attestation JWT in the `jwt` Header Parameter
//! binds the Client Identifier to the key that signs the request (OpenID4VP 1.0, Sections
//! 5.9.3 and 12).

use serde_json::{Map, Value};
use siros_codec::date::DateTime;

use super::signature::{by_request, strings, UriRule, Verifier};
use super::trust::{self, KeyMaterial, MetadataAnswer, TrustSubject};
use super::{Answers, AttestationFault, Halt, IntakeError};
use crate::client_id::ClientId;
use crate::jose::{self, Signed};
use crate::values::AttestationIssuer;
use crate::x509::Chain;

/// The `typ` of a Verifier Attestation JWT (Section 12).
const ATTESTATION_TYP: &str = "verifier-attestation+jwt";

/// Authenticates a request of a `verifier_attestation` client.
///
/// The attestation's `sub` is the Client Identifier, it is valid at `now`, its `cnf` key signs
/// the request, and its issuer's key signs the attestation: the leaf of the attestation's
/// `x5c`, or the key the host resolves for the issuer. The host's verdict on the issuer is the
/// verdict on the Verifier.
pub(super) fn authenticate(
    signed: &Signed,
    client_id: ClientId,
    now: DateTime,
    answers: &mut Answers<'_>,
) -> Result<Verifier, Halt> {
    let invalid = IntakeError::AttestationInvalid;
    let jwt = signed
        .text("jwt")
        .ok_or(invalid(AttestationFault::Absent))?;
    let (attestation, payload) =
        jose::compact(jwt).map_err(|e| invalid(AttestationFault::Jws(e)))?;
    if attestation.text("typ") != Some(ATTESTATION_TYP) {
        return Err(invalid(AttestationFault::Typ).into());
    }
    let claims = Claims::parse(&payload).ok_or(invalid(AttestationFault::Claims))?;
    if claims.sub != client_id.value() {
        return Err(IntakeError::AttestationSubjectMismatch.into());
    }
    if !claims.valid_at(now) {
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
            trust::verdict(
                answers,
                issuer,
                KeyMaterial::X509Chain(chain.into_certificates()),
            )?
        }
        None => {
            let resolved = trust::resolve(
                answers,
                issuer,
                attestation.kid(),
                None,
                MetadataAnswer::Refused,
            )?;
            attestation
                .verify(&resolved.key)
                .map_err(|_| IntakeError::AttestationSignatureInvalid)?;
            resolved.trusted
        }
    };
    let response_uri = claims.redirect_uris.map_or(UriRule::Any, UriRule::OneOf);
    Ok(by_request(client_id, trusted, response_uri))
}

/// A JWT NumericDate: seconds since 1970-01-01T00:00:00Z, fractional ones included (RFC 7519,
/// Section 2).
#[derive(Clone, Copy)]
struct NumericDate(f64);

impl NumericDate {
    fn of(value: &Value) -> Option<Self> {
        value.as_f64().map(Self)
    }

    /// Whether `now` is at or after this date.
    fn passed_at(self, now: DateTime) -> bool {
        now.unix() as f64 >= self.0
    }
}

/// The claims of a Verifier Attestation JWT this wallet reads (Section 12).
struct Claims {
    iss: AttestationIssuer,
    sub: String,
    exp: NumericDate,
    nbf: Option<NumericDate>,
    cnf: p256::PublicKey,
    redirect_uris: Option<Vec<String>>,
}

impl Claims {
    fn parse(payload: &[u8]) -> Option<Self> {
        let claims: Map<String, Value> = serde_json::from_slice(payload).ok()?;
        let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
        let nbf = match claims.get("nbf") {
            None => None,
            Some(nbf) => Some(NumericDate::of(nbf)?),
        };
        let redirect_uris = match claims.get("redirect_uris") {
            None => None,
            Some(uris) => Some(strings(uris)?),
        };
        Some(Self {
            iss: AttestationIssuer::new(text("iss")?),
            sub: text("sub")?,
            exp: NumericDate::of(claims.get("exp")?)?,
            nbf,
            cnf: jose::p256_key(claims.get("cnf")?.get("jwk")?)?,
            redirect_uris,
        })
    }

    /// Whether `now` is before `exp` and, when the attestation has one, at or after `nbf`
    /// (RFC 7519, Sections 4.1.4 and 4.1.5).
    fn valid_at(&self, now: DateTime) -> bool {
        !self.exp.passed_at(now) && self.nbf.is_none_or(|nbf| nbf.passed_at(now))
    }
}
