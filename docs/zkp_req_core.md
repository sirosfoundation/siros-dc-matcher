# The `zkp_req` core

`siros-zkp-req` and `siros-zkp-req-nym-auth` are one implementation of the `zkp_req` protocol
layer and of the nym_auth function catalogue, for the matcher, the wallet hosts and the verifier.
They implement the draft of the nym_auth rulebook repository at commit `e65861c`:
`zkp_req.md` (0.1), `nym_auth_rulebook.md` (0.5), `systems/longfellow-nym_auth-v1.md` and
`systems/vega-nym_auth-v1.md`.

## Acceptance gates

* **G1, honest path.** For each system (`urn:circuits:longfellow:nym_auth:v1` on
  `longfellow-libzk-v1`, `urn:circuits:vega:nym_auth:v1` on `vega-v1`): a request is matched,
  the test host signs the data to sign with a P-256 device key and runs a test prover, the
  presenter assembles the presentation, the presentation has the draft's structure when read
  by an independent CBOR decoder, and the Verifier's checks accept it. The pseudonym equals
  `SHA-256(DST ‖ secret_seed ‖ 0^32 ‖ SHA-256(verifier_id))`, written out in the test.
* **G2, differential.** For readdit's demo credential and the same session and proof time, the
  data to sign, e2 and the presentation fields equal readdit's under the draft's field mapping;
  each difference is one the draft makes.
* **G3, refusals.** One table holds one fixture per refusal rule: the request rules
  (`invalid_request`), `vp_formats_not_supported`, the Wallet codes of the system rulebooks'
  Section 9, and the Verifier's codes. Each row asserts the exact typed error.
* **G4, known answers.** The `age_check` examples of the specs, the 29 February cases worked by
  hand from the catalogue's rule, and the pseudonym and session vectors the provers ship.
* **G5, tamper.** A changed public input, a changed result and a presentation for another
  request each reach the proof check and are refused there.
* **G6, build.** The matcher stays within its size budget, UniFFI generates Kotlin and Swift,
  `cargo clippy --workspace --all-targets --all-features -- -D warnings` and
  `cargo fmt --all -- --check` are clean, and the picker crates build on Rust 1.82.
