//! The requests, credentials, certificates, metadata JWTs and host the tests share.

use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::cbor::Value as Cbor;
use siros_codec::date::DateTime;
use siros_credential::Credential;
use siros_dcql::DcqlQuery;
use siros_display::{DisplayCache, IssuerMetadata, Locale};
use siros_oid4vp::{FetchResponse, HttpStatus, RequestSignature, TransactionDataItem};
use siros_transaction_data::{
    Configuration, Context, Entry, EntryPosition, Fetched, Selection, Step,
};
use siros_trust::TrustStore;
use siros_wallet_state::WalletState;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::GeneralizedTime;
use x509_cert::der::Encode;
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

/// The documents the host serves, by URL.
pub type Documents = Vec<(String, FetchResponse)>;

/// The rows a card shows, label and value, or why it takes no entry.
pub type Shown = Result<Vec<(String, String)>, siros_transaction_data::Incompatibility>;

/// The time of the tests: 2026-10-26T12:00:00Z.
pub fn now() -> DateTime {
    DateTime::parse("2026-10-26T12:00:00Z").unwrap()
}

/// The Credential Issuer of the PaSO examples.
pub const ISSUER: &str = "https://issuer.bank.example";

/// The `vct` of the card of the PaSO examples.
pub const CARD: &str = "https://bank.example/sca/card";

/// Where the card's signed credential metadata is served (PaSO Proof Metadata, Annex A.1).
pub const METADATA_URI: &str = "https://issuer.bank.example/credential-metadata/BankPaymentCard";

/// The `transaction_data` string `raw`.
pub fn item(raw: &str) -> TransactionDataItem {
    TransactionDataItem::new(raw.to_owned())
}

/// base64url of the JSON text `text`, as a verifier sends an entry.
pub fn encode(text: &str) -> String {
    base64url::encode(text.as_bytes()).into()
}

/// The DCQL query of SD-JWT VC queries `ids` of `vct`, each requiring holder binding.
pub fn query(ids: &[&str], vct: &str) -> DcqlQuery {
    let credentials: Vec<Value> = ids
        .iter()
        .map(|id| json!({"id": id, "format": "dc+sd-jwt", "meta": {"vct_values": [vct]}}))
        .collect();
    DcqlQuery::from_json(&json!({"credentials": credentials}).to_string()).unwrap()
}

/// The entries of the JSON texts `texts`, against `query`.
pub fn entries(texts: &[String], query: &DcqlQuery) -> Vec<Entry> {
    texts
        .iter()
        .enumerate()
        .map(|(at, text)| {
            Entry::parse(EntryPosition::new(at), &item(&encode(text)), query).unwrap()
        })
        .collect()
}

/// The JSON texts of the elements of the JSON array text `text`.
pub fn elements(text: &str) -> Vec<String> {
    let value: Value = serde_json::from_str(text).unwrap();
    value
        .as_array()
        .unwrap()
        .iter()
        .map(Value::to_string)
        .collect()
}

/// A P-256 key of the fixed scalar `byte`.
pub fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32].into()).unwrap()
}

/// A certificate: its DER, and the key of its subject.
#[derive(Clone)]
pub struct Cert {
    pub der: Vec<u8>,
    pub key: SigningKey,
    pub subject: String,
}

impl Cert {
    /// A self-signed certificate authority of the key `byte`, named `cn`.
    pub fn root(cn: &str, byte: u8) -> Self {
        let subject = format!("CN={cn},O=Test only");
        let key = key(byte);
        Self {
            der: build(&subject, &subject, &key, &key, true),
            key,
            subject,
        }
    }

    /// An end-entity certificate of the key `byte`, named `cn`, that `issuer` signs.
    pub fn leaf(cn: &str, byte: u8, issuer: &Self) -> Self {
        let subject = format!("CN={cn},O=Test only");
        let key = key(byte);
        Self {
            der: build(&subject, &issuer.subject, &key, &issuer.key, false),
            key,
            subject,
        }
    }

    /// The base64 of the DER, as `x5c` carries it.
    pub fn x5c(&self) -> String {
        b64(&self.der)
    }
}

fn build(subject: &str, issuer: &str, key: &SigningKey, signer: &SigningKey, ca: bool) -> Vec<u8> {
    let time = |text: &str| {
        let unix = Duration::from_secs(DateTime::parse(text).unwrap().unix() as u64);
        Time::GeneralTime(GeneralizedTime::from_unix_duration(unix).unwrap())
    };
    let validity = Validity {
        not_before: time("2026-01-01T00:00:00Z"),
        not_after: time("2027-12-31T23:59:59Z"),
    };
    let mut builder = CertificateBuilder::new(
        Profile::Manual {
            issuer: Some(Name::from_str(issuer).unwrap()),
        },
        SerialNumber::new(&[0x01, subject.len() as u8]).unwrap(),
        validity,
        Name::from_str(subject).unwrap(),
        SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap(),
        signer,
    )
    .unwrap();
    if ca {
        builder
            .add_extension(&BasicConstraints {
                ca: true,
                path_len_constraint: None,
            })
            .unwrap();
    }
    builder
        .build::<p256::ecdsa::DerSignature>()
        .unwrap()
        .to_der()
        .unwrap()
}

/// The trust store of the anchors `roots`.
pub fn store(roots: &[&Cert]) -> TrustStore {
    let certificates: Vec<String> = roots.iter().map(|root| root.x5c()).collect();
    let record =
        json!([{"type": "etsi_tl", "value": "https://tl.example", "certificates": certificates}]);
    TrustStore::parse(&record.to_string()).unwrap()
}

/// The compact JWS of `header` and `payload`, signed with ES256 by `key`.
pub fn jwt(header: &Value, payload: &Value, key: &SigningKey) -> String {
    let input = format!(
        "{}.{}",
        base64url::encode(header.to_string().as_bytes()),
        base64url::encode(payload.to_string().as_bytes())
    );
    let signature: Signature = key.sign(input.as_bytes());
    format!("{input}.{}", base64url::encode(&signature.to_bytes()))
}

/// The SD-JWT VC of `vct` from the Credential Issuer [`ISSUER`], its issuer JWT with the `x5c`
/// chain `chain`; none when empty.
pub fn credential(vct: &str, chain: &[&Cert]) -> Credential {
    credential_with(vct, chain, &json!({}))
}

/// The SD-JWT VC of [`credential`] with the claims of `extra`.
pub fn credential_with(vct: &str, chain: &[&Cert], extra: &Value) -> Credential {
    let mut header = json!({"alg": "ES256", "typ": "dc+sd-jwt"});
    if !chain.is_empty() {
        header["x5c"] = json!(chain.iter().map(|c| c.x5c()).collect::<Vec<_>>());
    }
    let mut payload = json!({
        "iss": ISSUER,
        "vct": vct,
        "cnf": {"jwk": {"kty": "EC", "crv": "P-256", "x": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", "y": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}}
    });
    for (name, value) in extra.as_object().unwrap() {
        payload[name] = value.clone();
    }
    let sd_jwt = format!(
        "{}.{}.{}~",
        base64url::encode(header.to_string().as_bytes()),
        base64url::encode(payload.to_string().as_bytes()),
        base64url::encode(&[7; 64]),
    );
    held("dc+sd-jwt", &sd_jwt)
}

/// The credential of the wallet state entry of `format` and `data`.
fn held(format: &str, data: &str) -> Credential {
    let state = json!({
        "schemaVersion": 4,
        "credentials": [{
            "credentialId": 1, "format": format, "data": data, "kid": "key-1", "instanceId": 0,
            "batchId": 1, "credentialIssuerIdentifier": ISSUER,
            "credentialConfigurationId": "card"
        }],
        "keypairs": [], "presentations": [], "settings": {}, "credentialIssuanceSessions": []
    });
    let state = WalletState::parse(&state.to_string()).unwrap();
    Credential::parse(&state.credentials()[0]).unwrap()
}

/// The display metadata of the card's configuration, its signed credential metadata at
/// `uri` when given.
pub fn display(uri: Option<&str>) -> DisplayCache {
    let mut configuration = json!({"format": "dc+sd-jwt", "vct": CARD});
    if let Some(uri) = uri {
        configuration["credential_metadata_uri"] = json!(uri);
    }
    let issuer = json!({
        "credential_issuer": ISSUER,
        "credential_configurations_supported": {"card": configuration}
    });
    let metadata = IssuerMetadata::merge(&issuer, "card", None).unwrap();
    DisplayCache::new(vec![metadata], Vec::new()).unwrap()
}

/// A `200` response holding `body`.
pub fn ok(body: &[u8]) -> FetchResponse {
    FetchResponse::new(HttpStatus::OK, None, body.to_vec())
}

/// What the host gives the selection: trust, display metadata, configuration, the documents it
/// answers fetches with, the wallet's language and whether the request is signed.
pub struct Host {
    pub trust: TrustStore,
    pub display: DisplayCache,
    pub configuration: Configuration,
    pub documents: Documents,
    pub language: Locale,
    pub signature: RequestSignature,
}

impl Host {
    /// A host with no anchor, no metadata, the configuration `configuration`, English, and a
    /// signed request.
    pub fn new(configuration: Value) -> Self {
        Self {
            trust: TrustStore::parse("[]").unwrap(),
            display: display(None),
            configuration: Configuration::parse(&configuration.to_string()).unwrap(),
            documents: Vec::new(),
            language: Locale::parse("en").unwrap(),
            signature: RequestSignature::Signed,
        }
    }

    /// The host in the wallet's language `tag`.
    pub fn speaking(mut self, tag: &str) -> Self {
        self.language = Locale::parse(tag).unwrap();
        self
    }

    /// What `credential` takes of `entries`, each fetch answered from the documents, a URL
    /// without one with `404`.
    pub fn select(
        &self,
        entries: &[&Entry],
        credential: &Credential,
    ) -> Result<Selection, siros_transaction_data::TransactionDataError> {
        let mut fetched = Fetched::new();
        loop {
            let context = Context {
                trust: &self.trust,
                fetched: &fetched,
                display: &self.display,
                configuration: &self.configuration,
                language: &self.language,
                signature: self.signature,
                now: now(),
            };
            let fetch = match context.first_match(entries, credential)? {
                Step::Done(selection) => return Ok(selection),
                Step::Fetch(fetch) => fetch,
            };
            let response = self
                .documents
                .iter()
                .find(|(url, _)| url == fetch.url().as_str())
                .map(|(_, response)| response.clone())
                .unwrap_or_else(|| FetchResponse::new(HttpStatus::new(404), None, Vec::new()));
            assert!(fetched.insert_first(&fetch, response).is_ok());
        }
    }
}

/// A host configuration entry: `definition` for the type `type_id` of credentials of `vct`.
pub fn configured(type_id: &str, vct: &str, definition: &Value) -> Value {
    json!({"type": type_id, "vct_values": [vct], "definition": definition})
}

/// SRI integrity metadata of `bytes`: `sha256-` and the base64 of their SHA-256.
pub fn sri(bytes: &[u8]) -> String {
    format!("sha256-{}", b64(&Sha256::digest(bytes)))
}

/// The padded base64 of `bytes` (RFC 4648, Section 4).
pub fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// An mdoc of one element.
pub fn mdoc() -> Credential {
    let text = |s: &str| Cbor::Text(s.to_owned());
    let map = |entries: Vec<(&str, Cbor)>| {
        Cbor::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
    };
    let tagged = |item: &Cbor| Cbor::Tag(24, Box::new(Cbor::Bytes(item.encode())));
    let tdate = |t: &str| Cbor::Tag(0, Box::new(text(t)));
    let item = tagged(&map(vec![
        ("digestID", Cbor::Unsigned(0)),
        ("random", Cbor::Bytes(vec![0x11; 16])),
        ("elementIdentifier", text("family_name")),
        ("elementValue", text("Doe")),
    ]));
    let digest = Cbor::Bytes(Sha256::digest(item.encode()).to_vec());
    let mso = map(vec![
        ("version", text("1.0")),
        ("digestAlgorithm", text("SHA-256")),
        (
            "valueDigests",
            Cbor::Map(vec![(
                text("org.iso.18013.5.1"),
                Cbor::Map(vec![(Cbor::Unsigned(0), digest)]),
            )]),
        ),
        (
            "deviceKeyInfo",
            map(vec![(
                "deviceKey",
                Cbor::Map(vec![
                    (Cbor::Unsigned(1), Cbor::Unsigned(2)),
                    (Cbor::Negative(0), Cbor::Unsigned(1)),
                    (Cbor::Negative(1), Cbor::Bytes(vec![0x01; 32])),
                    (Cbor::Negative(2), Cbor::Bytes(vec![0x02; 32])),
                ]),
            )]),
        ),
        ("docType", text("org.iso.18013.5.1.mDL")),
        (
            "validityInfo",
            map(vec![
                ("signed", tdate("2026-01-01T00:00:00Z")),
                ("validFrom", tdate("2026-01-01T00:00:00Z")),
                ("validUntil", tdate("2027-01-01T00:00:00Z")),
            ]),
        ),
    ]);
    let issuer_signed = map(vec![
        (
            "nameSpaces",
            Cbor::Map(vec![(text("org.iso.18013.5.1"), Cbor::Array(vec![item]))]),
        ),
        (
            "issuerAuth",
            Cbor::Array(vec![
                Cbor::Bytes(vec![0xa1, 0x01, 0x26]),
                Cbor::Map(vec![(
                    Cbor::Unsigned(33),
                    Cbor::Bytes(include_bytes!("vectors/issuer.der").to_vec()),
                )]),
                Cbor::Bytes(tagged(&mso).encode()),
                Cbor::Bytes(vec![0; 64]),
            ]),
        ),
    ]);
    held(
        "mso_mdoc",
        base64url::encode(&issuer_signed.encode()).as_str(),
    )
}

/// The entry an honest selection takes.
pub fn taken(selection: &Selection) -> &siros_transaction_data::Taken {
    match selection {
        Selection::Takes(taken) => taken,
        Selection::Excluded(causes) => panic!("excluded: {causes:?}"),
    }
}

pub const PAYMENT: &str = "urn:eudi:sca:payment:1";
pub const LOGIN: &str = "urn:eudi:sca:login_risk_transaction:1";
pub const ACCESS: &str = "urn:eudi:sca:account_access:1";
pub const MANDATE: &str = "urn:eudi:sca:emandate:1";

/// `value` with the members of `changes`; a `null` change removes the member.
pub fn with(mut value: Value, changes: Value) -> Value {
    let object = value.as_object_mut().unwrap();
    for (name, change) in changes.as_object().unwrap() {
        if change.is_null() {
            assert!(object.remove(name).is_some(), "{name}");
        } else {
            object.insert(name.clone(), change.clone());
        }
    }
    value
}

/// A payment payload of EC TS12 v1.0.1, Section 4.3.1.
pub fn payment() -> Value {
    json!({
        "transaction_id": "tx-0001",
        "payee": {"name": "Shop AB", "id": "SE1234567890"},
        "currency": "EUR",
        "amount": 49.99
    })
}

/// The entry of `transaction_type` with the payload of the JSON text `payload`, naming `pay`
/// and accepting SHA-256, as a verifier writes it.
pub fn ts12_entry(transaction_type: &str, payload: &str) -> String {
    format!(
        r#"{{"type":{},"credential_ids":["pay"],"transaction_data_hashes_alg":["sha-256"],"payload":{payload}}}"#,
        Value::from(transaction_type)
    )
}

/// Whether the TS12 payload parser of `transaction_type` accepts the payload of the JSON text
/// `payload`: `Ok`, or the code of the refusal of the entry or of the payload.
pub fn ts12_payload(transaction_type: &str, payload: &str) -> Result<(), &'static str> {
    let query = query(&["pay"], CARD);
    let raw = encode(&ts12_entry(transaction_type, payload));
    let entry = Entry::parse(EntryPosition::new(0), &item(&raw), &query).map_err(|e| e.code())?;
    let host = Host::new(json!([configured(
        transaction_type,
        CARD,
        &json!({"claims": []})
    )]));
    match host.select(&[&entry], &credential(CARD, &[])).unwrap() {
        Selection::Excluded(causes) => match causes.as_slice() {
            [(_, siros_transaction_data::Incompatibility::Ts12Payload(fault))] => Err(fault.code()),
            _ => Ok(()),
        },
        Selection::Takes(_) => Ok(()),
    }
}

/// The rows `host` shows for the entry `credential` takes of `entry`, each label with its value
/// as text, or why the credential takes none.
pub fn rows(host: &Host, entry: &Entry, credential: &Credential) -> Shown {
    use siros_transaction_data::RowValue;
    match host.select(&[entry], credential).unwrap() {
        Selection::Takes(taken) => Ok(taken
            .view()
            .rows()
            .iter()
            .map(|row| {
                let value = match row.value() {
                    RowValue::Value(value) => value.text(),
                    RowValue::LabelOnly => "-".to_owned(),
                    RowValue::Image(image) => format!("<image {:?}>", image.format()),
                };
                (row.label().text().to_owned(), value)
            })
            .collect()),
        Selection::Excluded(mut causes) => Err(causes.remove(0).1),
    }
}
