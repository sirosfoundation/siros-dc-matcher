//! A `zkp_req` Credential Query (`zkp_req`, Sections 1.1, 2 and 2.1).

use serde_json::{Map, Value};

use crate::outcome::RequestRule;

/// The Credential Format Identifier of a `zkp_req` query.
pub const FORMAT: &str = "zkp_req";

/// A `return` handle: a non-empty string of ASCII letters, digits, `_` and `-` (Section 2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReturnHandle(String);

impl ReturnHandle {
    /// The handle, when `text` has the syntax of Section 2.
    pub fn parse(text: &str) -> Option<Self> {
        let valid = !text.is_empty()
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        valid.then(|| Self(text.to_owned()))
    }

    /// The handle's text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One `_req` item (Section 2).
#[derive(Debug, Clone, PartialEq)]
pub struct ReqItem {
    /// `fn_id`: a function of the catalogue of the credential's type.
    pub fn_id: String,
    /// `return`: the handle of the result. Absent for an assertion.
    pub ret: Option<ReturnHandle>,
    /// `params`, as sent. Empty when absent: each parameter then takes its default.
    pub params: Map<String, Value>,
}

/// One option: the `_req` items the Verifier accepts together (Section 2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOption {
    /// The option's index in `_req_sets`, which the presentation carries as `req_set`. `None`
    /// for the one option of a query without `_req_sets`.
    pub req_set: Option<usize>,
    /// The `_req` indexes of the option, in the Verifier's order, each once.
    pub items: Vec<usize>,
}

/// The credential type a query asks for: `meta`, read for its `source_format`
/// (Section 1.1).
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialType {
    /// `mso_mdoc`, with `doctype_value` (OpenID4VP 1.0, B.2.3).
    MsoMdoc {
        /// `doctype_value`.
        doctype: String,
    },
    /// `dc+sd-jwt`, with `vct_values` (OpenID4VP 1.0, B.3.5).
    SdJwt {
        /// `vct_values`.
        vct_values: Vec<String>,
    },
    /// `jwt_vc_json` or `ldp_vc`, with `type_values` (OpenID4VP 1.0, B.1.1).
    W3c {
        /// The source format.
        source_format: String,
        /// `type_values`.
        type_values: Vec<Vec<String>>,
    },
    /// A format whose own profile defines its `meta` members, such as `bbs_cd`.
    Profiled {
        /// The source format.
        source_format: String,
        /// The `meta` members other than `source_format`, as sent.
        meta: Map<String, Value>,
    },
}

impl CredentialType {
    /// `meta.source_format`.
    pub fn source_format(&self) -> &str {
        match self {
            Self::MsoMdoc { .. } => "mso_mdoc",
            Self::SdJwt { .. } => "dc+sd-jwt",
            Self::W3c { source_format, .. } | Self::Profiled { source_format, .. } => source_format,
        }
    }
}

/// One entry of `trusted_authorities` (OpenID4VP 1.0, Section 6.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAuthority {
    /// `type`.
    pub kind: AuthorityKind,
    /// `values`, non-empty.
    pub values: Vec<String>,
}

/// The `type` of a trusted authority (OpenID4VP 1.0, Section 6.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityKind {
    /// `aki`: base64url KeyIdentifiers of an Authority Key Identifier.
    Aki,
    /// `etsi_tl`: ETSI Trusted List identifiers.
    EtsiTl,
    /// `openid_federation`: OpenID Federation Entity Identifiers.
    OpenidFederation,
    /// A type this version does not define.
    Other(String),
}

/// A parsed `zkp_req` Credential Query.
#[derive(Debug, Clone, PartialEq)]
pub struct ZkpReqQuery {
    /// `id`.
    pub id: String,
    /// `meta`, read for its source format.
    pub credential_type: CredentialType,
    /// `_req`, in order. An item's index identifies it.
    pub items: Vec<ReqItem>,
    /// The options, in the Verifier's order of preference.
    pub options: Vec<QueryOption>,
    /// Whether the query has `_req_sets`.
    pub has_req_sets: bool,
    /// `trusted_authorities`, when present.
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    /// `require_cryptographic_holder_binding`; `true` when absent (OpenID4VP 1.0, Section 6.1).
    pub require_holder_binding: bool,
}

impl ZkpReqQuery {
    /// Parses one Credential Query (one element of `dcql_query.credentials`).
    ///
    /// # Errors
    ///
    /// [`RequestRule`]: the first rule of Sections 1.1, 2 and 2.1 the query breaks.
    pub fn parse(query: &Value) -> Result<Self, RequestRule> {
        let query = query.as_object().ok_or(RequestRule::QueryNotObject)?;
        let id = match query.get("id") {
            Some(Value::String(id)) if !id.is_empty() => id.clone(),
            _ => return Err(RequestRule::QueryIdInvalid),
        };
        if query.get("format").and_then(Value::as_str) != Some(FORMAT) {
            return Err(RequestRule::FormatNotZkpReq);
        }
        if query.contains_key("claims") {
            return Err(RequestRule::ClaimsPresent);
        }
        if query.contains_key("claim_sets") {
            return Err(RequestRule::ClaimSetsPresent);
        }
        let credential_type = read_meta(query.get("meta"))?;
        let items = read_items(query.get("_req"))?;
        let (options, has_req_sets) = read_options(query.get("_req_sets"), items.len())?;
        Ok(Self {
            id,
            credential_type,
            items,
            options,
            has_req_sets,
            trusted_authorities: read_authorities(query.get("trusted_authorities"))?,
            require_holder_binding: read_holder_binding(
                query.get("require_cryptographic_holder_binding"),
            )?,
        })
    }

    /// The option with index `req_set` of `_req_sets`, or the one option without them.
    pub fn option(&self, req_set: Option<usize>) -> Option<&QueryOption> {
        self.options.iter().find(|o| o.req_set == req_set)
    }
}

fn read_meta(meta: Option<&Value>) -> Result<CredentialType, RequestRule> {
    let meta = meta
        .and_then(Value::as_object)
        .ok_or(RequestRule::MetaInvalid)?;
    let source_format = meta
        .get("source_format")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(RequestRule::SourceFormatInvalid)?;
    match source_format {
        "mso_mdoc" => match meta.get("doctype_value") {
            Some(Value::String(doctype)) => Ok(CredentialType::MsoMdoc {
                doctype: doctype.clone(),
            }),
            _ => Err(RequestRule::TypeValueInvalid),
        },
        "dc+sd-jwt" => Ok(CredentialType::SdJwt {
            vct_values: strings(meta.get("vct_values")).ok_or(RequestRule::TypeValueInvalid)?,
        }),
        "jwt_vc_json" | "ldp_vc" => Ok(CredentialType::W3c {
            source_format: source_format.to_owned(),
            type_values: type_values(meta.get("type_values"))
                .ok_or(RequestRule::TypeValueInvalid)?,
        }),
        _ => {
            let mut members = meta.clone();
            members.remove("source_format");
            Ok(CredentialType::Profiled {
                source_format: source_format.to_owned(),
                meta: members,
            })
        }
    }
}

/// A non-empty array of strings.
fn strings(value: Option<&Value>) -> Option<Vec<String>> {
    let list: Vec<String> = value?
        .as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    (!list.is_empty()).then_some(list)
}

fn type_values(value: Option<&Value>) -> Option<Vec<Vec<String>>> {
    let list: Vec<Vec<String>> = value?
        .as_array()?
        .iter()
        .map(|v| strings(Some(v)))
        .collect::<Option<_>>()?;
    (!list.is_empty()).then_some(list)
}

fn read_items(req: Option<&Value>) -> Result<Vec<ReqItem>, RequestRule> {
    let items = match req {
        Some(Value::Array(items)) if !items.is_empty() => items,
        _ => return Err(RequestRule::ReqInvalid),
    };
    let mut out: Vec<ReqItem> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item = read_item(item, index)?;
        let repeated = item
            .ret
            .as_ref()
            .is_some_and(|handle| out.iter().any(|seen| seen.ret.as_ref() == Some(handle)));
        if repeated {
            return Err(RequestRule::ReturnRepeated { item: index });
        }
        out.push(item);
    }
    Ok(out)
}

fn read_item(item: &Value, index: usize) -> Result<ReqItem, RequestRule> {
    let item = item
        .as_object()
        .ok_or(RequestRule::ItemNotObject { item: index })?;
    if item
        .keys()
        .any(|k| !matches!(k.as_str(), "fn_id" | "params" | "return"))
    {
        return Err(RequestRule::ItemMemberUnknown { item: index });
    }
    let fn_id = match item.get("fn_id") {
        Some(Value::String(f)) if !f.is_empty() => f.clone(),
        _ => return Err(RequestRule::FnIdInvalid { item: index }),
    };
    let params = match item.get("params") {
        None => Map::new(),
        Some(Value::Object(params)) => params.clone(),
        Some(_) => return Err(RequestRule::ParamsNotObject { item: index }),
    };
    let ret = match item.get("return") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(ReturnHandle::parse)
                .ok_or(RequestRule::ReturnInvalid { item: index })?,
        ),
    };
    Ok(ReqItem { fn_id, ret, params })
}

fn read_options(
    sets: Option<&Value>,
    items: usize,
) -> Result<(Vec<QueryOption>, bool), RequestRule> {
    let Some(sets) = sets else {
        let all = QueryOption {
            req_set: None,
            items: (0..items).collect(),
        };
        return Ok((vec![all], false));
    };
    let sets = match sets {
        Value::Array(sets) if !sets.is_empty() => sets,
        _ => return Err(RequestRule::ReqSetsInvalid),
    };
    let options = sets
        .iter()
        .enumerate()
        .map(|(index, set)| read_option(set, index, items))
        .collect::<Result<_, _>>()?;
    Ok((options, true))
}

fn read_option(set: &Value, index: usize, items: usize) -> Result<QueryOption, RequestRule> {
    let invalid = RequestRule::OptionInvalid { option: index };
    let set = match set {
        Value::Array(set) if !set.is_empty() => set,
        _ => return Err(invalid),
    };
    let mut out: Vec<usize> = Vec::with_capacity(set.len());
    for entry in set {
        let item = entry
            .as_u64()
            .and_then(|i| usize::try_from(i).ok())
            .filter(|i| *i < items)
            .ok_or(invalid)?;
        if out.contains(&item) {
            return Err(invalid);
        }
        out.push(item);
    }
    Ok(QueryOption {
        req_set: Some(index),
        items: out,
    })
}

fn read_authorities(value: Option<&Value>) -> Result<Option<Vec<TrustedAuthority>>, RequestRule> {
    let Some(value) = value else {
        return Ok(None);
    };
    let read = |entry: &Value| -> Option<TrustedAuthority> {
        let entry = entry.as_object()?;
        let kind = match entry.get("type")?.as_str()? {
            "aki" => AuthorityKind::Aki,
            "etsi_tl" => AuthorityKind::EtsiTl,
            "openid_federation" => AuthorityKind::OpenidFederation,
            other => AuthorityKind::Other(other.to_owned()),
        };
        Some(TrustedAuthority {
            kind,
            values: strings(entry.get("values"))?,
        })
    };
    let list: Option<Vec<TrustedAuthority>> = value
        .as_array()
        .filter(|a| !a.is_empty())
        .and_then(|a| a.iter().map(read).collect());
    list.map(Some).ok_or(RequestRule::TrustedAuthoritiesInvalid)
}

fn read_holder_binding(value: Option<&Value>) -> Result<bool, RequestRule> {
    match value {
        None => Ok(true),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(RequestRule::HolderBindingInvalid),
    }
}
