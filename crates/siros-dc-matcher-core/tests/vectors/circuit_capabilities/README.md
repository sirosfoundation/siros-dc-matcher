# circuit capabilities match vectors

`match.json` is a verbatim copy of go-zk-circuits
`testvectors/capabilities/match.json` (branch `feat/circuit-capabilities`,
commit `f0a7784`, sha256
`9bee1868fd957fd4ad56a91dbca93b922ede04bfa57bb0f8b3a3c9bd5f383866`). It is the
catalog's reference vector file for its `Match` helper. The matcher is held to
it by `tests/circuit_capabilities.rs`.

**This copy is a snapshot of an unmerged branch.** When go-zk-circuits merges,
re-copy the file from its final path, update the commit and hash above, and
re-run `cargo test -p siros-dc-matcher-core --test circuit_capabilities`. Do
not edit this copy: a vector changed here stops being shared.

## What the matcher is held to, and what it is not

The matcher implements steps 3 to 5 of the rule (`Capabilities::serves`). For
each case the test applies the wallet's side (steps 1 and 2: the `proofSystems`
and `circuitIds` filters, aliases, `revoked`) and then compares the set of
served circuit ids with `expect`.

- **Ranking is not checked.** `expect` is ordered (active before deprecated,
  profile preference, id tie-break); the matcher does not rank circuits, a
  wallet does, so the test compares sets. The `profile-*`,
  `deprecated-ranks-below-active` and `id-tiebreak` cases therefore pin
  membership only. `conformsToProfiles` and `credential.profile` are not read
  by the matcher.
- **`expectError` cases** (a request without presentation, credential format or
  credential type) cannot arise in the matcher, whose presentation is fixed
  at `circuit_zk` and whose format and type come from the profile and `meta`.
  The test requires that nothing is served for them.
- **`credential.format`** is compared against the formats the profile maps
  `circuit_zk` onto (stored `mso_mdoc`), not against a request member, because
  a `circuit_zk` request does not carry one.
- **`empty-req`** is served by `serves` as the vectors say. A real request
  never reaches it: the planner rejects an empty `req` as structurally invalid.
