//! The presentation as sent and its Key Binding JWT (RFC 9901, Sections 4.3 and 4.3.1).

use rustc_hash::FxHashSet;
use serde_json::Value;
use siros_codec::base64url;

use crate::alg::HashAlg;
use crate::error::KeyBindingError;

/// The KB-JWT header. The host signs with ES256.
const HEADER: &str = r#"{"typ":"kb+jwt","alg":"ES256"}"#;

/// The payload claims Section 4.3 requires.
const REQUIRED: [&str; 4] = ["iat", "aud", "nonce", "sd_hash"];

/// An SD-JWT as sent to a verifier: the issuer JWT, then the selected disclosures, each
/// followed by `~` (Section 4).
pub struct Presentation {
    text: String,
    alg: HashAlg,
}

impl Presentation {
    pub(crate) fn new(text: String, alg: HashAlg) -> Self {
        Self { text, alg }
    }

    /// The compact form, sent alone when the verifier requires no key binding.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The presentation with the signing input of its KB-JWT.
    ///
    /// The payload holds `iat` (seconds since the epoch), `aud`, `nonce`, and `sd_hash` over
    /// [`as_str`](Self::as_str) with the credential's `_sd_alg` (Section 4.3.1), then the
    /// `extra` claims in their order.
    ///
    /// # Errors
    ///
    /// [`KeyBindingError::ClaimCollision`]: an extra claim repeats one of the four or another
    /// extra claim.
    pub fn key_binding(
        self,
        iat: u64,
        aud: &str,
        nonce: &str,
        extra: &[(String, Value)],
    ) -> Result<KeyBinding, KeyBindingError> {
        let mut names = FxHashSet::default();
        for (name, _) in extra {
            if REQUIRED.contains(&name.as_str()) || !names.insert(name.as_str()) {
                return Err(KeyBindingError::ClaimCollision);
            }
        }
        let sd_hash = self.alg.digest(self.text.as_bytes());
        let mut payload = format!(
            r#"{{"iat":{iat},"aud":{},"nonce":{},"sd_hash":"{sd_hash}""#,
            json_string(aud),
            json_string(nonce),
        );
        for (name, value) in extra {
            payload.push(',');
            payload.push_str(&json_string(name));
            payload.push(':');
            payload.push_str(&value.to_string());
        }
        payload.push('}');
        let signing_input = format!(
            "{}.{}",
            base64url::encode(HEADER.as_bytes()),
            base64url::encode(payload.as_bytes()),
        );
        Ok(KeyBinding {
            presentation: self.text,
            signing_input,
        })
    }
}

/// `text` as a JSON string.
fn json_string(text: &str) -> String {
    Value::from(text).to_string()
}

/// A presentation and the signing input of the KB-JWT bound to it.
pub struct KeyBinding {
    presentation: String,
    signing_input: String,
}

impl KeyBinding {
    /// The bytes the host signs: the KB-JWT's encoded header and payload, joined by `.` (RFC
    /// 7515, Section 5.1).
    pub fn signing_input(&self) -> &[u8] {
        self.signing_input.as_bytes()
    }

    /// The SD-JWT+KB: the presentation, then the KB-JWT that `signature` completes.
    /// `signature` is the raw `r ‖ s` ES256 signature over the signing input (RFC 7518,
    /// Section 3.4).
    pub fn assemble(self, signature: &[u8; 64]) -> String {
        let mut sd_jwt_kb = self.presentation;
        sd_jwt_kb.push_str(&self.signing_input);
        sd_jwt_kb.push('.');
        sd_jwt_kb.push_str(&base64url::encode(signature));
        sd_jwt_kb
    }
}
