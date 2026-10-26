//! A signed Request Object authenticated under the rule of its Client Identifier Prefix
//! (OpenID4VP 1.0, Section 5.9.3).

use serde_json::Value;
use sha2::{Digest, Sha256};
use siros_codec::base64url;

use super::trust::{self, KeyMaterial, TrustSubject};
use super::{attestation, Answers, Halt, IntakeError};
use crate::client_id::{ClientId, ClientIdPrefix};
use crate::jose::Signed;
use crate::x509::Chain;

/// The `typ` of a Request Object (RFC 9101, Section 10.8).
const REQUEST_OBJECT_TYP: &str = "oauth-authz-req+jwt";

/// Who sent a request, as intake established it.
pub(super) struct Verifier {
    pub(super) client_id: ClientId,
    pub(super) trusted: bool,
    pub(super) metadata: Metadata,
    pub(super) response_uri: UriRule,
}

/// Where the Verifier metadata comes from.
pub(super) enum Metadata {
    /// `client_metadata` of the request.
    Request,
    /// The Trust Chain of an `openid_federation` client; `client_metadata` is ignored.
    TrustChain(Option<Value>),
}

/// What the `response_uri` of a redirect request must be, beyond an `https` URL.
pub(super) enum UriRule {
    /// Any.
    Any,
    /// Exactly this value; the value when the request omits it (`redirect_uri` prefix).
    Equals(String),
    /// A URL whose host is this DNS name (untrusted `x509_san_dns` client).
    Host(String),
    /// One of these (`redirect_uris` of a Verifier Attestation JWT).
    OneOf(Vec<String>),
}

/// Authenticates the Request Object `signed` of `client_id`: its `typ`, the binding of its key
/// to the Client Identifier, its signature, and the host's trust verdict.
pub(super) fn authenticate(
    signed: &Signed,
    client_id: ClientId,
    now_unix: u64,
    answers: &mut Answers<'_>,
) -> Result<Verifier, Halt> {
    if signed.text("typ") != Some(REQUEST_OBJECT_TYP) {
        return Err(IntakeError::TypMismatch.into());
    }
    match client_id.prefix() {
        ClientIdPrefix::RedirectUri => Err(IntakeError::SignedRedirectUri.into()),
        ClientIdPrefix::X509SanDns => {
            let chain = Chain::parse(signed.header().get("x5c"))?;
            if !chain.names_dns(client_id.value()) {
                return Err(IntakeError::SanMismatch.into());
            }
            signed.verify(chain.key())?;
            let dns = client_id.value().to_owned();
            let trusted = trust::verdict(
                answers,
                TrustSubject::Client(client_id.clone()),
                KeyMaterial::X509Chain(chain.into_der()),
            )?;
            // Section 5.9.3: without trust in the Client Identifier, the FQDN of the Response
            // URI is the DNS name.
            let response_uri = if trusted {
                UriRule::Any
            } else {
                UriRule::Host(dns)
            };
            Ok(by_request(client_id, trusted, response_uri))
        }
        ClientIdPrefix::X509Hash => {
            let chain = Chain::parse(signed.header().get("x5c"))?;
            let hash = base64url::encode(&Sha256::digest(chain.leaf()));
            if hash != client_id.value() {
                return Err(IntakeError::CertificateHashMismatch.into());
            }
            signed.verify(chain.key())?;
            let trusted = trust::verdict(
                answers,
                TrustSubject::Client(client_id.clone()),
                KeyMaterial::X509Chain(chain.into_der()),
            )?;
            Ok(by_request(client_id, trusted, UriRule::Any))
        }
        ClientIdPrefix::DecentralizedIdentifier => {
            // The key is a verification method of the DID: `kid` is a DID URL of it.
            let kid = signed
                .text("kid")
                .filter(|kid| {
                    kid.strip_prefix(client_id.value())
                        .is_some_and(|fragment| fragment.len() > 1 && fragment.starts_with('#'))
                })
                .ok_or(IntakeError::KidNotOfClient)?
                .to_owned();
            let resolved = trust::resolve(
                answers,
                TrustSubject::Client(client_id.clone()),
                Some(kid),
                None,
                false,
            )?;
            signed.verify(&resolved.key)?;
            Ok(by_request(client_id, resolved.trusted, UriRule::Any))
        }
        ClientIdPrefix::VerifierAttestation => {
            attestation::authenticate(signed, client_id, now_unix, answers)
        }
        ClientIdPrefix::OpenidFederation => {
            let trust_chain = match signed.header().get("trust_chain") {
                None => None,
                Some(chain) => Some(strings(chain).ok_or(IntakeError::JwsMalformed)?),
            };
            let resolved = trust::resolve(
                answers,
                TrustSubject::Client(client_id.clone()),
                signed.text("kid").map(str::to_owned),
                trust_chain,
                true,
            )?;
            signed.verify(&resolved.key)?;
            Ok(Verifier {
                client_id,
                trusted: resolved.trusted,
                metadata: Metadata::TrustChain(resolved.metadata),
                response_uri: UriRule::Any,
            })
        }
    }
}

/// A Verifier whose metadata is the request's `client_metadata`.
pub(super) fn by_request(client_id: ClientId, trusted: bool, response_uri: UriRule) -> Verifier {
    Verifier {
        client_id,
        trusted,
        metadata: Metadata::Request,
        response_uri,
    }
}

/// A JSON array of strings.
pub(super) fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|s| s.as_str().map(str::to_owned))
        .collect()
}
