//! The `zkp_req` entry of `vp_formats_supported` (`zkp_req`, Section 1.2).

use serde_json::Value;

use crate::outcome::RequestRule;

/// What the Verifier says it can verify.
///
/// Both lists are non-empty. They may name identifiers this Wallet does not know: Section 1.2
/// tells Wallets to ignore those, so they never match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpFormats {
    /// `proof_backend_values`.
    pub proof_backends: Vec<String>,
    /// `system_id_values`.
    pub systems: Vec<String>,
}

impl ZkpFormats {
    /// Reads `vp_formats_supported.zkp_req` from a request's `client_metadata`.
    ///
    /// # Errors
    ///
    /// [`RequestRule::FormatsMissing`] when the entry is absent: Section 1.2 says the Verifier
    /// MUST send both lists. The list rules otherwise.
    pub fn from_client_metadata(client_metadata: &Value) -> Result<Self, RequestRule> {
        let entry = client_metadata
            .get("vp_formats_supported")
            .and_then(|f| f.get("zkp_req"))
            .and_then(Value::as_object)
            .ok_or(RequestRule::FormatsMissing)?;
        Ok(Self {
            proof_backends: list(entry.get("proof_backend_values"))
                .ok_or(RequestRule::ProofBackendValuesInvalid)?,
            systems: list(entry.get("system_id_values"))
                .ok_or(RequestRule::SystemIdValuesInvalid)?,
        })
    }

    /// Whether the Verifier lists `system`.
    pub fn lists_system(&self, system: &str) -> bool {
        self.systems.iter().any(|s| s == system)
    }

    /// Whether the Verifier lists `backend`.
    pub fn lists_backend(&self, backend: &str) -> bool {
        self.proof_backends.iter().any(|b| b == backend)
    }
}

fn list(value: Option<&Value>) -> Option<Vec<String>> {
    let list: Vec<String> = value?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    (!list.is_empty()).then_some(list)
}
