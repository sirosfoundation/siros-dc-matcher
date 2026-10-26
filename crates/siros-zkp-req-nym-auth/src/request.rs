//! A verified request that meets the nym_auth policy (N2; nym_auth catalogue, "Binding",
//! "Response confidentiality" and "Verifier identity").

use siros_oid4vp::{ClientIdPrefix, Protocol, ResponseMode, VerifiedRequest};

use crate::policy::{PolicyRule, RequestRefusal};
use crate::presenter::Session;
use crate::verifier_id::{Intermediary, VerifierId, VerifierIdForm, VerifierIdRule};

/// The `format` of a registration certificate in `verifier_info` (ETSI TS 119 472-2 V1.2.1,
/// OIDFVP-HAIP-COMMON-REQ-RO-15).
const REGISTRATION_CERTIFICATE: &str = "registration_cert";

/// A request intake verified that meets the nym_auth policy, with the session it binds.
#[derive(Debug, Clone)]
pub struct NymAuthRequest<'r> {
    request: &'r VerifiedRequest,
    session: Session,
}

impl<'r> NymAuthRequest<'r> {
    /// The nym_auth request of `request`, its `verifier_id` in the form `verifier_id`.
    ///
    /// The request is signed: its Client Identifier has a prefix other than `redirect_uri`, and
    /// over the Digital Credentials API it arrived as `openid4vp-v1-signed`, the calling origin
    /// in `expected_origins`. The host's trust verdict on the Client Identifier is positive.
    /// The Response Mode is `direct_post.cwt` or `direct_post.jwt` over redirects and
    /// `dc_api.jwt` over the Digital Credentials API, which intake gives an encryption key. The
    /// session's `Handover` binds that key's thumbprint.
    ///
    /// The `verifier_id` derives from the request: the Client Identifier in the `x509_san_dns`
    /// form, `"semantic_id:"` and the access certificate's semantic identifier in the
    /// `semantic` form. A request that carries a registration certificate in `verifier_info` is
    /// refused: the catalogue takes the semantic identifier from it and refuses the
    /// `x509_san_dns` form when it names an intermediary, and no intake authenticates it.
    ///
    /// # Errors
    ///
    /// [`RequestRefusal`]: the first rule `request` breaks.
    pub fn new(
        request: &'r VerifiedRequest,
        verifier_id: VerifierIdForm,
    ) -> Result<Self, RequestRefusal> {
        let policy = RequestRefusal::Policy;
        let verifier = request.verifier();
        let client_id = verifier
            .client_id()
            .filter(|c| c.prefix() != ClientIdPrefix::RedirectUri)
            .ok_or(policy(PolicyRule::Unsigned))?;
        if request.dc_api_protocol() == Some(Protocol::Multisigned) {
            return Err(policy(PolicyRule::Multisigned));
        }
        if !verifier.trusted() {
            return Err(policy(PolicyRule::Untrusted));
        }
        let encrypted = matches!(
            (request.origin(), request.response_mode()),
            (
                None,
                ResponseMode::DirectPostCwt | ResponseMode::DirectPostJwt
            ) | (Some(_), ResponseMode::DcApiJwt)
        );
        if !encrypted {
            return Err(policy(PolicyRule::ResponseMode));
        }
        let registered = request
            .verifier_info_formats()
            .iter()
            .any(|format| format.as_str() == REGISTRATION_CERTIFICATE);
        if registered {
            return Err(RequestRefusal::VerifierId(
                VerifierIdRule::RegistrationCertificate,
            ));
        }
        let verifier_id = match verifier_id {
            VerifierIdForm::X509SanDns => VerifierId::x509_san_dns(client_id, Intermediary::Absent),
            VerifierIdForm::Semantic => semantic_id(request),
        }
        .map_err(RequestRefusal::VerifierId)?;
        Ok(Self {
            request,
            session: Session {
                handover: request.handover(),
                verifier_id,
            },
        })
    }

    /// The request.
    pub fn request(&self) -> &'r VerifiedRequest {
        self.request
    }

    /// The session: the request's `Handover` and the Verifier's `verifier_id`.
    pub fn session(&self) -> &Session {
        &self.session
    }
}

/// The `semantic` form of `request`'s `verifier_id`: from the semantics identifier of its access
/// certificate.
fn semantic_id(request: &VerifiedRequest) -> Result<VerifierId, VerifierIdRule> {
    let certificate = request
        .access_certificate()
        .ok_or(VerifierIdRule::SemanticIdMissing)?;
    let identifier = certificate
        .semantic_identifier()
        .map_err(VerifierIdRule::SemanticId)?;
    Ok(VerifierId::semantic(identifier))
}
