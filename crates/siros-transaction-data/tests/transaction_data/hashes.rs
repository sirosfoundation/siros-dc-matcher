//! The hash vectors of `tests/vectors/transaction-data-hashes.json` (see `tests/vectors/SOURCE`):
//! each `transaction_data` string hashed as received (OpenID4VP 1.0, B.3.3.1).

use serde_json::Value;
use siros_oid4vp::TransactionDataItem;
use siros_transaction_data::HashAlg;

#[test]
fn each_entry_is_hashed_as_received() {
    let document: Value =
        serde_json::from_str(include_str!("../vectors/transaction-data-hashes.json")).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for vector in vectors {
        let raw = vector["raw"].as_str().unwrap();
        for alg in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512] {
            let expected = vector["hashes"][alg.identifier()].as_str().unwrap();
            assert_eq!(
                alg.hash(&TransactionDataItem::new(raw.to_owned())),
                expected,
                "{} {}",
                vector["name"],
                alg.identifier()
            );
        }
    }
}
