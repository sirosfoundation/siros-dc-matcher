//! The verifier: its requests, through intake.

use std::str::FromStr;
use std::time::Duration;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{DerSignature, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use siros_codec::base64url;
use siros_codec::date::DateTime;
use siros_oid4vp::{
    Effect, EffectResult, IntakeError, IntakeState, Origin, Step, TrustAnswer, Verdict,
    VerifiedRequest,
};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::asn1::ObjectIdentifier;
use x509_cert::der::asn1::{Ia5String, UtcTime};
use x509_cert::der::Encode;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::CertificatePolicies;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};

/// 2026-10-09T12:00:00Z, the time of nym_auth's test issuer.
pub const NOW: i64 = 1_791_547_200;
/// The DNS name of the verifier, in its certificate and its URLs.
pub const DNS: &str = "verifier.example";
pub const RESPONSE_URI: &str = "https://verifier.example/response";
pub const ORIGIN: &str = "https://verifier.example";
pub const NONCE: &str = "n-0S6_WzA2Mj";
pub const STATE: &str = "s-1";

/// A deterministic generator (SplitMix64) standing in for the host's CSPRNG.
pub struct Rng(pub u64);

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Rng {}

pub fn b64(bytes: &[u8]) -> String {
    base64url::encode(bytes).into_string()
}

/// The verifier's response encryption key.
pub fn recipient() -> SecretKey {
    SecretKey::from_bytes(&[21; 32].into()).unwrap()
}

fn coordinates() -> (String, String) {
    let point = recipient().public_key().to_encoded_point(false);
    (b64(point.x().unwrap()), b64(point.y().unwrap()))
}

/// The JWK of the response encryption key.
pub fn encryption_jwk() -> Value {
    let (x, y) = coordinates();
    json!({"kty": "EC", "crv": "P-256", "alg": "ECDH-ES", "use": "enc", "kid": "enc-1", "x": x, "y": y})
}

/// The verifier metadata: the encryption key and the `zkp_req` lists.
pub fn client_metadata() -> Value {
    json!({
        "jwks": {"keys": [encryption_jwk()]},
        "vp_formats_supported": {"zkp_req": {
            "proof_backend_values": ["longfellow-libzk-v1", "vega-v1"],
            "system_id_values": ["urn:circuits:longfellow:nym_auth:v1", "urn:circuits:vega:nym_auth:v1"]
        }}
    })
}

/// Intake of `state` to its end, the host trusting every subject.
pub fn intake(state: IntakeState) -> VerifiedRequest {
    intake_with(state, Verdict::Trusted).unwrap()
}

/// Intake of `state` to its end, the host's trust verdict `trusted` on every subject.
pub fn intake_with(
    mut state: IntakeState,
    verdict: Verdict,
) -> Result<VerifiedRequest, IntakeError> {
    loop {
        match state.step()? {
            Step::Verified(request) => return Ok(*request),
            Step::Effect(Effect::Trust(_)) => {
                state.answer(EffectResult::Trusted(TrustAnswer::new(verdict, None, None)))
            }
            Step::Effect(other) => panic!("no fetch expected: {other:?}"),
        }
    }
}

fn wallet_formats() -> Map<String, Value> {
    Map::new()
}

/// A `redirect_uri` client's request, by value, with the parameters `params`.
pub fn redirect_unsigned(params: &Value) -> VerifiedRequest {
    let mut uri = String::from("openid4vp://?");
    let mut first = true;
    let client_id = format!("redirect_uri:{RESPONSE_URI}");
    let mut pairs: Vec<(String, String)> = vec![("client_id".into(), client_id)];
    for (name, value) in params.as_object().unwrap() {
        let text = match value {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        pairs.push((name.clone(), text));
    }
    for (name, value) in pairs {
        if !first {
            uri.push('&');
        }
        first = false;
        uri.push_str(&name);
        uri.push('=');
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                uri.push(char::from(byte));
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    intake(IntakeState::redirect(
        &uri,
        wallet_formats(),
        DateTime::from_unix(NOW).unwrap(),
        &mut Rng(7),
    ))
}

/// How the verifier signs its Request Object: the subject and the certificate policy of its
/// access certificate, and its Client Identifier Prefix.
#[derive(Clone, Copy)]
pub struct Signer {
    pub subject: &'static str,
    pub policy: &'static str,
    pub prefix: SignedPrefix,
}

/// The Client Identifier Prefix of a signed request.
#[derive(Clone, Copy)]
pub enum SignedPrefix {
    X509SanDns,
    X509Hash,
}

/// The DC API protocol of a signed request: a compact JWS under `openid4vp-v1-signed`, or a JWS
/// JSON Serialization under `openid4vp-v1-multisigned`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignedForm {
    Compact,
    Multisigned,
}

/// NCP-n-eudiwrp: an access certificate issued to a natural person (ETSI TS 119 411-8).
pub const NATURAL_POLICY: &str = "0.4.0.194118.1.1";
/// NCP-l-eudiwrp: an access certificate issued to a legal person (ETSI TS 119 411-8).
pub const LEGAL_POLICY: &str = "0.4.0.194118.1.2";

/// An `x509_san_dns` client whose access certificate names a legal person by its VAT number
/// (ETSI EN 319 412-1, LEG-5.1.4).
pub const SIGNER: Signer = Signer {
    subject: "CN=Test verifier,O=Test only,2.5.4.97=VATBE-0876866142",
    policy: LEGAL_POLICY,
    prefix: SignedPrefix::X509SanDns,
};

/// The verifier's signing key and its self-signed certificate of `signer`'s subject and policy,
/// with the dNSName SAN [`DNS`].
fn certificate(signer: Signer) -> (SigningKey, Vec<u8>) {
    let key = SigningKey::from_bytes(&[5; 32].into()).unwrap();
    let at =
        |unix: u64| Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(unix)).unwrap());
    let validity = Validity {
        not_before: at(1_767_225_600),
        not_after: at(1_893_456_000),
    };
    let spki = SubjectPublicKeyInfoOwned::from_key(*key.verifying_key()).unwrap();
    let mut builder = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::new(&[1]).unwrap(),
        validity,
        Name::from_str(signer.subject).unwrap(),
        spki,
        &key,
    )
    .unwrap();
    builder
        .add_extension(&SubjectAltName(vec![GeneralName::DnsName(
            Ia5String::new(DNS).unwrap(),
        )]))
        .unwrap();
    let policy = PolicyInformation {
        policy_identifier: ObjectIdentifier::new(signer.policy).unwrap(),
        policy_qualifiers: None,
    };
    builder
        .add_extension(&CertificatePolicies(vec![policy]))
        .unwrap();
    let der = builder.build::<DerSignature>().unwrap().to_der().unwrap();
    (key, der)
}

/// The client identifier of the signed requests.
pub fn signed_client_id() -> String {
    format!("x509_san_dns:{DNS}")
}

impl Signer {
    /// The Client Identifier.
    pub fn client_id(self) -> String {
        match self.prefix {
            SignedPrefix::X509Hash => {
                let (_, der) = certificate(self);
                format!("x509_hash:{}", b64(&Sha256::digest(&der)))
            }
            SignedPrefix::X509SanDns => signed_client_id(),
        }
    }

    /// The protected header of a Request Object, with `x5c`.
    pub fn header(self) -> Value {
        let (_, der) = certificate(self);
        let mut x5c = base64url::encode(&der)
            .into_string()
            .replace('-', "+")
            .replace('_', "/");
        while x5c.len() % 4 != 0 {
            x5c.push('=');
        }
        json!({"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [x5c]})
    }

    /// The signature of `input`, `r ‖ s`, base64url.
    pub fn sign(self, input: &str) -> String {
        let (key, _) = certificate(self);
        let signature: Signature = key.sign(input.as_bytes());
        b64(&signature.to_bytes())
    }

    /// `request_object` as a compact JWS.
    pub fn compact(self, request_object: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(self.header().to_string().as_bytes()),
            b64(request_object.to_string().as_bytes())
        );
        format!("{input}.{}", self.sign(&input))
    }
}

/// A signed Request Object by value over redirects, with the members of `params`.
pub fn redirect_signed(params: &Value) -> VerifiedRequest {
    intake(redirect_signed_state(params, SIGNER))
}

/// The intake of a Request Object `signer` signs, by value over redirects, with the members of
/// `params`.
pub fn redirect_signed_state(params: &Value, signer: Signer) -> IntakeState {
    let mut object = params.clone();
    object["client_id"] = signer.client_id().into();
    object["response_uri"] = RESPONSE_URI.into();
    let jws = signer.compact(&object);
    let uri = format!(
        "openid4vp://?client_id={}&request={jws}",
        signer.client_id()
    );
    IntakeState::redirect(
        &uri,
        wallet_formats(),
        DateTime::from_unix(NOW).unwrap(),
        &mut Rng(9),
    )
}

/// The DC API request of one entry, `protocol` and its `data`, as the browser sends it.
pub fn dc_api_request(protocol: &str, data: Value) -> Vec<u8> {
    json!({"requests": [{"protocol": protocol, "data": data}]})
        .to_string()
        .into_bytes()
}

/// The intake of the DC API request `request` from [`ORIGIN`].
pub fn dc_api_intake(request: &[u8]) -> IntakeState {
    IntakeState::dc_api(
        request,
        Origin::new(ORIGIN),
        DateTime::from_unix(NOW).unwrap(),
    )
}

/// The intake of a DC API request of one entry from [`ORIGIN`].
fn dc_api_state(protocol: &str, data: Value) -> IntakeState {
    dc_api_intake(&dc_api_request(protocol, data))
}

/// An unsigned DC API request of `params`.
pub fn dc_api_unsigned(params: &Value) -> VerifiedRequest {
    intake(dc_api_state("openid4vp-v1-unsigned", params.clone()))
}

/// A signed DC API request of `params`, which expects [`ORIGIN`].
pub fn dc_api_signed(params: &Value) -> VerifiedRequest {
    intake(dc_api_signed_state(params, SIGNER, SignedForm::Compact))
}

/// The intake of a DC API request of `params` that `signer` signs, which expects [`ORIGIN`]:
/// `openid4vp-v1-signed` for [`SignedForm::Compact`], `openid4vp-v1-multisigned` with one
/// signature for [`SignedForm::Multisigned`].
pub fn dc_api_signed_state(params: &Value, signer: Signer, form: SignedForm) -> IntakeState {
    dc_api_intake(&dc_api_signed_request(params, signer, form))
}

/// The DC API request of `params` that `signer` signs, which expects [`ORIGIN`]:
/// `openid4vp-v1-signed` for [`SignedForm::Compact`], `openid4vp-v1-multisigned` with one
/// signature for [`SignedForm::Multisigned`].
pub fn dc_api_signed_request(params: &Value, signer: Signer, form: SignedForm) -> Vec<u8> {
    let mut object = params.clone();
    object["expected_origins"] = json!([ORIGIN]);
    if form == SignedForm::Compact {
        object["client_id"] = signer.client_id().into();
        return dc_api_request(
            "openid4vp-v1-signed",
            json!({"request": signer.compact(&object)}),
        );
    }
    // A.3.2.2: `client_id` travels in the protected header of each signature.
    let mut header = signer.header();
    header["client_id"] = signer.client_id().into();
    let protected = b64(header.to_string().as_bytes());
    let payload = b64(object.to_string().as_bytes());
    let signature = signer.sign(&format!("{protected}.{payload}"));
    dc_api_request(
        "openid4vp-v1-multisigned",
        json!({"payload": payload, "signatures": [{"protected": protected, "signature": signature}]}),
    )
}
