//! A verified request that meets the nym_auth policy (N2; nym_auth catalogue, "Binding",
//! "Response confidentiality" and "Verifier identity").

use siros_oid4vp::{ClientIdPrefix, ResponseMode, VerifiedRequest};

use crate::policy::{PolicyRule, RequestRefusal};
use crate::presenter::Session;
use crate::verifier_id::VerifierIdForm;

/// A request intake verified that is signed, asks for an encrypted response, and names a
/// Verifier of the trust framework's `verifier_id` form, with the session it binds.
#[derive(Debug, Clone)]
pub struct NymAuthRequest<'r> {
    request: &'r VerifiedRequest,
    session: Session,
}

impl<'r> NymAuthRequest<'r> {
    /// The nym_auth request of `request`, with its `verifier_id` in the form `verifier_id`.
    ///
    /// The request is signed: its Client Identifier has a prefix other than `redirect_uri`, and
    /// intake verified its signature and, over the Digital Credentials API, the calling origin
    /// in `expected_origins`. Its Response Mode is `direct_post.cwt` or `direct_post.jwt` over
    /// redirects and `dc_api.jwt` over the Digital Credentials API, encrypted to a key of
    /// `client_metadata`. The session's `Handover` binds that key's thumbprint.
    ///
    /// # Errors
    ///
    /// [`RequestRefusal`]: the first rule `request` breaks.
    pub fn new(
        request: &'r VerifiedRequest,
        verifier_id: &VerifierIdForm,
    ) -> Result<Self, RequestRefusal> {
        let client_id = request
            .verifier()
            .client_id()
            .filter(|c| c.prefix() != ClientIdPrefix::RedirectUri)
            .ok_or(RequestRefusal::Policy(PolicyRule::Unsigned))?;
        let encrypted = matches!(
            (request.origin(), request.response_mode()),
            (
                None,
                ResponseMode::DirectPostCwt | ResponseMode::DirectPostJwt
            ) | (Some(_), ResponseMode::DcApiJwt)
        );
        if !encrypted {
            return Err(RequestRefusal::Policy(PolicyRule::ResponseMode));
        }
        if request.encryption().is_none() {
            return Err(RequestRefusal::Policy(PolicyRule::EncryptionKeyMissing));
        }
        let verifier_id = verifier_id
            .verifier_id(client_id.as_str())
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
