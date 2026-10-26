//! A4 and A5: a selection parses only against the plan it was made on, and the signatures only
//! against the `Sign` effects they answer, each under the key its effect names.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::Signature;
use serde_json::json;
use siros_codec::cbor::Value as Cbor;
use siros_presentation::{Fulfilment, PresentationError, Selection, Sign, SignId};
use siros_zkp_req_nym_auth::testing::{self, TestProver};

use crate::verifier::{b64, redirect_unsigned, Rng, NONCE, STATE};
use crate::wallet::{mdoc, ready, sd_jwt, sign_all, Held, Wallet, MDL, MDL_NS, VCT};

#[test]
fn selections_and_signatures_parse_against_the_plan() {
    let wallet = Wallet::new(vec![
        Held::new(
            1,
            "dc+sd-jwt",
            sd_jwt(VCT, &[("given_name", json!("Erika"))]),
        ),
        Held::new(
            2,
            "mso_mdoc",
            mdoc(MDL, MDL_NS, &[("family_name", Cbor::text("Doe"))]),
        ),
    ]);
    let request = redirect_unsigned(&json!({
        "response_type": "vp_token",
        "response_mode": "direct_post",
        "nonce": NONCE,
        "state": STATE,
        "dcql_query": {
            "credentials": [
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": [VCT]},
                 "claims": [{"path": ["given_name"]}]},
                {"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": MDL},
                 "claims": [{"path": [MDL_NS, "family_name"]}]}
            ],
            "credential_sets": [
                {"options": [["pid"]]},
                {"options": [["mdl"]], "required": false}
            ]
        }
    }));
    let fetches = wallet.fetches(&request);
    let input = wallet.input(&request, &fetches);
    let digest = ready(&input).unwrap().view().digest().to_owned();
    let other = b64(&[0; 32]);

    // A4: (case, digest, offer, additions, refusal)
    type Case<'d> = (
        &'d str,
        &'d str,
        usize,
        Vec<usize>,
        Option<PresentationError>,
    );
    let selections: [Case<'_>; 6] = [
        ("the plan's offer and addition", &digest, 0, vec![0], None),
        (
            "a digest not of 32 bytes",
            "AAAA",
            0,
            vec![],
            Some(PresentationError::DigestMalformed),
        ),
        (
            "another plan",
            &other,
            0,
            vec![],
            Some(PresentationError::DigestMismatch),
        ),
        (
            "an unknown offer",
            &digest,
            1,
            vec![],
            Some(PresentationError::OfferUnknown),
        ),
        (
            "an unknown addition",
            &digest,
            0,
            vec![1],
            Some(PresentationError::AdditionUnknown),
        ),
        (
            "an addition twice",
            &digest,
            0,
            vec![0, 0],
            Some(PresentationError::AdditionConflict),
        ),
    ];
    let planned = ready(&input).unwrap();
    for (case, digest, offer, additions, refusal) in selections {
        let chosen = Selection::new(digest, offer, additions, Vec::new())
            .and_then(|selection| planned.choose(&selection, Fulfilment::WalletUi));
        assert_eq!(chosen.err(), refusal, "{case}");
    }

    // A5: (case, the signatures from the honest ones, refusal)
    type Edit = fn(&[Sign], &mut Vec<(SignId, Vec<u8>)>);
    let signatures: [(&str, Edit, Option<PresentationError>); 6] = [
        ("every signature once", |_, _| {}, None),
        (
            "one missing",
            |_, s| drop(s.pop()),
            Some(PresentationError::SignatureMissing),
        ),
        (
            "one twice",
            |_, s| s.push(s[0].clone()),
            Some(PresentationError::SignatureRepeated),
        ),
        (
            "one of no effect",
            |_, s| s.push((SignId::new(s.len()), s[0].1.clone())),
            Some(PresentationError::SignatureUnknown),
        ),
        (
            "one not 64 bytes",
            |_, s| s[0].1.truncate(63),
            Some(PresentationError::SignatureLength),
        ),
        (
            "one under another key",
            |signs, s| {
                let other: Signature = testing::key(0x55).sign(signs[0].input());
                s[0].1 = other.to_bytes().to_vec();
            },
            Some(PresentationError::SignatureInvalid),
        ),
    ];
    for (case, edit, refusal) in signatures {
        let chosen = planned
            .choose(
                &Selection::new(&digest, 0, vec![0], Vec::new()).unwrap(),
                Fulfilment::WalletUi,
            )
            .unwrap();
        let mut rng = Rng(3);
        let prepared = chosen.prepare(&mut rng).unwrap();
        assert_eq!(
            prepared.signs().len(),
            2,
            "the KB-JWT and the DeviceAuthentication"
        );
        let mut signed = sign_all(prepared.signs());
        edit(prepared.signs(), &mut signed);
        let response = prepared.finish(signed, &TestProver { fail: None }, &mut rng);
        assert_eq!(response.err(), refusal, "{case}");
    }
}
