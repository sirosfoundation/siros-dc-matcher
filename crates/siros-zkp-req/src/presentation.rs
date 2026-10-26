//! The presentation (`zkp_req`, Section 4), the `Proof` its proof backends share, and the
//! `vp_token` (Section 6.1).

use std::fmt;

use siros_codec::base64url;
use siros_codec::cbor::{self, CborError, Item, Kind, Value};

/// A member of a CBOR map this module reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Member {
    /// `system_id`.
    SystemId,
    /// `proof_backend`.
    ProofBackend,
    /// `req_set`.
    ReqSet,
    /// `proof`.
    Proof,
    /// `results`.
    Results,
    /// `inputs` of `Proof`.
    Inputs,
    /// `zk_proof` of `Proof`.
    ZkProof,
}

impl Member {
    /// The member's name.
    pub fn name(self) -> &'static str {
        match self {
            Self::SystemId => "system_id",
            Self::ProofBackend => "proof_backend",
            Self::ReqSet => "req_set",
            Self::Proof => "proof",
            Self::Results => "results",
            Self::Inputs => "inputs",
            Self::ZkProof => "zk_proof",
        }
    }
}

/// Why bytes are not a [`ZkpPresentation`] or a [`ProofEnvelope`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    /// Not one CBOR item the strict reader accepts.
    Cbor(CborError),
    /// The item is not a map.
    NotMap,
    /// A map key is not a text string, or a member this structure does not define.
    UnknownMember,
    /// A required member is absent.
    Missing(Member),
    /// A member has the wrong CBOR type.
    WrongType(Member),
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(e) => e.fmt(f),
            Self::NotMap => f.write_str("not a CBOR map"),
            Self::UnknownMember => f.write_str("unknown member"),
            Self::Missing(m) => write!(f, "{} is missing", m.name()),
            Self::WrongType(m) => write!(f, "{} has the wrong type", m.name()),
        }
    }
}

impl std::error::Error for EncodingError {}

impl From<CborError> for EncodingError {
    fn from(e: CborError) -> Self {
        Self::Cbor(e)
    }
}

/// `ZkpPresentation` (Section 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpPresentation {
    /// `system_id`.
    pub system_id: String,
    /// `proof_backend`.
    pub proof_backend: String,
    /// `req_set`: present exactly when the query has `_req_sets` (Section 2.1).
    pub req_set: Option<u64>,
    /// `proof`, defined by the proof backend specification.
    pub proof: Vec<u8>,
    /// `results`: each `return` handle of the answered option and its result (Section 3).
    pub results: Vec<(String, Value)>,
}

impl ZkpPresentation {
    /// The presentation as a CBOR value.
    pub fn to_value(&self) -> Value {
        let mut members = vec![
            (Value::text("system_id"), Value::text(&self.system_id)),
            (
                Value::text("proof_backend"),
                Value::text(&self.proof_backend),
            ),
            (Value::text("proof"), Value::Bytes(self.proof.clone())),
            (Value::text("results"), text_map(&self.results)),
        ];
        if let Some(req_set) = self.req_set {
            members.push((Value::text("req_set"), Value::Unsigned(req_set)));
        }
        Value::Map(members)
    }

    /// The deterministic CBOR encoding.
    pub fn encode(&self) -> Vec<u8> {
        self.to_value().encode()
    }

    /// Reads a presentation from untrusted bytes.
    ///
    /// # Errors
    ///
    /// [`EncodingError`]: the bytes are not one CBOR map with exactly the members of Section 4,
    /// each of its type.
    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let item = cbor::decode(bytes)?;
        let entries = item.as_map().ok_or(EncodingError::NotMap)?;
        let mut p = Partial::default();
        for (key, value) in entries {
            p.read(key, value)?;
        }
        p.finish()
    }
}

#[derive(Default)]
struct Partial {
    system_id: Option<String>,
    proof_backend: Option<String>,
    req_set: Option<u64>,
    proof: Option<Vec<u8>>,
    results: Option<Vec<(String, Value)>>,
}

impl Partial {
    fn read(&mut self, key: &Item<'_>, value: &Item<'_>) -> Result<(), EncodingError> {
        let wrong = EncodingError::WrongType;
        match key.as_text() {
            Some("system_id") => self.system_id = Some(text(value, Member::SystemId)?),
            Some("proof_backend") => self.proof_backend = Some(text(value, Member::ProofBackend)?),
            Some("req_set") => match value.kind() {
                Kind::Unsigned(n) => self.req_set = Some(*n),
                _ => return Err(wrong(Member::ReqSet)),
            },
            Some("proof") => {
                let bytes = value.as_bytes().ok_or(wrong(Member::Proof))?;
                self.proof = Some(bytes.to_vec());
            }
            Some("results") => self.results = Some(read_text_map(value, Member::Results)?),
            _ => return Err(EncodingError::UnknownMember),
        }
        Ok(())
    }

    fn finish(self) -> Result<ZkpPresentation, EncodingError> {
        let missing = EncodingError::Missing;
        Ok(ZkpPresentation {
            system_id: self.system_id.ok_or(missing(Member::SystemId))?,
            proof_backend: self.proof_backend.ok_or(missing(Member::ProofBackend))?,
            req_set: self.req_set,
            proof: self.proof.ok_or(missing(Member::Proof))?,
            results: self.results.ok_or(missing(Member::Results))?,
        })
    }
}

fn text(item: &Item<'_>, member: Member) -> Result<String, EncodingError> {
    item.as_text()
        .map(str::to_owned)
        .ok_or(EncodingError::WrongType(member))
}

/// A map from text keys to any values.
fn read_text_map(item: &Item<'_>, member: Member) -> Result<Vec<(String, Value)>, EncodingError> {
    let entries = item.as_map().ok_or(EncodingError::WrongType(member))?;
    entries
        .iter()
        .map(|(k, v)| {
            let key = k.as_text().ok_or(EncodingError::WrongType(member))?;
            Ok((key.to_owned(), Value::from_item(v)))
        })
        .collect()
}

fn text_map(entries: &[(String, Value)]) -> Value {
    Value::Map(
        entries
            .iter()
            .map(|(k, v)| (Value::text(k), v.clone()))
            .collect(),
    )
}

/// `Proof = { "inputs": { * tstr => any }, "zk_proof": bstr }`, the content of `proof` for the
/// proof backends `longfellow-libzk-v1`, `vega-v1` and `bbs-cd-plugins-v0.1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofEnvelope {
    /// `inputs`: the prover-supplied values the system rulebook names.
    pub inputs: Vec<(String, Value)>,
    /// `zk_proof`.
    pub zk_proof: Vec<u8>,
}

impl ProofEnvelope {
    /// The deterministic CBOR encoding: the bytes of `proof`.
    pub fn encode(&self) -> Vec<u8> {
        Value::Map(vec![
            (Value::text("inputs"), text_map(&self.inputs)),
            (Value::text("zk_proof"), Value::Bytes(self.zk_proof.clone())),
        ])
        .encode()
    }

    /// Reads `Proof` from the bytes of `proof`.
    ///
    /// # Errors
    ///
    /// [`EncodingError`]: a member of `Proof` is missing, repeated, unknown or of the wrong
    /// type, or bytes follow the map. The system checks the members of `inputs`.
    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let item = cbor::decode(bytes)?;
        let entries = item.as_map().ok_or(EncodingError::NotMap)?;
        let (mut inputs, mut zk_proof) = (None, None);
        for (key, value) in entries {
            match key.as_text() {
                Some("inputs") => inputs = Some(read_text_map(value, Member::Inputs)?),
                Some("zk_proof") => {
                    let bytes = value
                        .as_bytes()
                        .ok_or(EncodingError::WrongType(Member::ZkProof))?;
                    zk_proof = Some(bytes.to_vec());
                }
                _ => return Err(EncodingError::UnknownMember),
            }
        }
        Ok(Self {
            inputs: inputs.ok_or(EncodingError::Missing(Member::Inputs))?,
            zk_proof: zk_proof.ok_or(EncodingError::Missing(Member::ZkProof))?,
        })
    }
}

/// The `vp_token` of the answered queries, as JSON Response Modes carry it (Section 6.1): each
/// presentation is the base64url, without padding, of its CBOR encoding.
pub fn vp_token_json(answers: &[(String, Vec<ZkpPresentation>)]) -> serde_json::Value {
    let map = answers
        .iter()
        .map(|(query_id, presentations)| {
            let list = presentations
                .iter()
                .map(|p| serde_json::Value::String(base64url::encode(&p.encode()).into()))
                .collect();
            (query_id.clone(), serde_json::Value::Array(list))
        })
        .collect();
    serde_json::Value::Object(map)
}

/// The `vp_token` as `direct_post.cwt` carries it (Section 6.1): each presentation is the map
/// itself.
pub fn vp_token_cbor(answers: &[(String, Vec<ZkpPresentation>)]) -> Value {
    Value::Map(
        answers
            .iter()
            .map(|(query_id, presentations)| {
                let list = presentations
                    .iter()
                    .map(ZkpPresentation::to_value)
                    .collect();
                (Value::text(query_id), Value::Array(list))
            })
            .collect(),
    )
}
