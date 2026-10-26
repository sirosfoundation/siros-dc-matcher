//! Prints, as JSON, what readdit's nym-longfellow and nym-vega compute for a credential of the
//! test issuer, a redirect session, and a v0.4 presentation of fixed parts.

use serde_json::{json, Value};
use siros_zkp_req_nym_auth::testing::{
    encryption_jwk, issue, Issuer, Spec, CLIENT_ID, NONCE, RESPONSE_URI, SEED,
};

const PROOF_TIME: &str = "2026-10-09T12:00:00Z";
const PROOF: [u8; 64] = [7; 64];

fn longfellow(credential: &str, thumbprint: &[u8; 32]) -> Value {
    use nym_longfellow::{circuit, handover, mdoc, presentation, witness, x509};
    let transcript = handover::session_transcript(CLIENT_ID, NONCE, Some(thumbprint), RESPONSE_URI);
    let m = mdoc::parse(credential).expect("nym-longfellow reads the credential");
    let signer = x509::parse(&m.document_signer).expect("nym-longfellow reads the certificate");
    let verifier_input = nym_longfellow::sha256(CLIENT_ID.as_bytes());
    let pseudonym = witness::pseudonym(&SEED, &verifier_input);
    let v0_4 = presentation::Presentation {
        system_id: circuit::CIRCUIT_ID.into(),
        proof: PROOF.to_vec(),
        issuer_key_set: vec![m.document_signer.clone()],
        proof_time: PROOF_TIME.into(),
        results: vec![
            (
                "nym".into(),
                presentation::ResultValue::Pseudonym(pseudonym),
            ),
            ("adult".into(), presentation::ResultValue::True),
        ],
    }
    .encode()
    .expect("nym-longfellow encodes");
    json!({
        "session_transcript": hex::encode(&transcript),
        "device_message": hex::encode(handover::device_message(&transcript, circuit::DOC_TYPE)),
        "challenge_digest": hex::encode(handover::challenge_digest(&transcript, circuit::DOC_TYPE)),
        "mdoc": {
            "sig_structure": hex::encode(&m.signed),
            "issuer_signature": hex::encode([m.r, m.s].concat()),
            "birth_date_item": hex::encode(&m.birth_item),
            "ssc_item": hex::encode(&m.ssc_item),
            "document_signer": hex::encode(&m.document_signer),
            "doc_type": m.doc_type,
            "device_key": [hex::encode(m.device_key.x), hex::encode(m.device_key.y)],
            "valid_from": m.valid_from.text(),
            "valid_until": m.valid_until.text(),
            "birth_date": m.birth_date.text(),
            "ssc": hex::encode(m.ssc),
            "digests_listed": m.digests_listed(),
        },
        "issuer_key": [hex::encode(signer.key.x), hex::encode(signer.key.y)],
        "verifier_input": hex::encode(verifier_input),
        "pseudonym": hex::encode(pseudonym),
        "presentation_v0_4": hex::encode(&v0_4),
    })
}

fn vega(credential: &str, thumbprint: &[u8; 32]) -> Value {
    use nym_vega::{circuit, handover, mdoc, x509};
    use vega_age::pseudonym;
    let transcript = handover::session_transcript(CLIENT_ID, NONCE, Some(thumbprint), RESPONSE_URI);
    let m = mdoc::parse(credential).expect("nym-vega reads the credential");
    let signer = x509::parse(&m.document_signer).expect("nym-vega reads the certificate");
    let verifier_input = pseudonym::verifier_input(CLIENT_ID);
    let item = |id: &str| {
        m.items
            .iter()
            .find(|(name, _)| name == id)
            .map(|(_, bytes)| hex::encode(bytes))
            .expect("nym-vega lists the item")
    };
    json!({
        "session_transcript": hex::encode(&transcript),
        "device_message": hex::encode(handover::device_message(&transcript, circuit::DOC_TYPE)),
        "challenge_digest": hex::encode(handover::challenge_digest(&transcript, circuit::DOC_TYPE)),
        "mdoc": {
            "sig_structure": hex::encode(&m.sig_structure),
            "issuer_signature": hex::encode([m.r, m.s].concat()),
            "birth_date_item": item(circuit::BIRTH_DATE),
            "ssc_item": item(circuit::SSC),
            "document_signer": hex::encode(&m.document_signer),
            "doc_type": m.doc_type,
            "device_key": [hex::encode(m.device_key.x), hex::encode(m.device_key.y)],
            "valid_from": m.valid_from.text(),
            "valid_until": m.valid_until.text(),
        },
        "issuer_key": [hex::encode(signer.key.x), hex::encode(signer.key.y)],
        "verifier_input": hex::encode(verifier_input),
        "pseudonym": hex::encode(pseudonym::pseudonym(&SEED, &verifier_input)),
    })
}

fn main() {
    let ds = Issuer::root(0x11, "Test Document Signer");
    let credential = issue(&ds, &Spec::default());
    let thumbprint = siros_oid4vp::ec_jwk_thumbprint(&encryption_jwk()).expect("an EC key");
    let out = json!({
        "provenance": "Computed by readdit-demo 1cf3f26 (native/longfellow/nym-longfellow, native/vega/nym-vega) with scripts/readdit-differential.",
        "inputs": {
            "client_id": CLIENT_ID, "nonce": NONCE, "response_uri": RESPONSE_URI,
            "jwk_thumbprint": hex::encode(thumbprint), "secret_seed": hex::encode(SEED),
            "credential": credential, "proof": hex::encode(PROOF), "proof_time": PROOF_TIME,
        },
        "longfellow": longfellow(&credential, &thumbprint),
        "vega": vega(&credential, &thumbprint),
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("JSON"));
}
