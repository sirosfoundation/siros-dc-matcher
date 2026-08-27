# Contributing

## Provenance

**Read this before writing any matching code.** It is committed ahead of the
implementation on purpose — a provenance rule written after someone has read the
source it governs is worth nothing.

This repository is an independent implementation of the OpenID4VP DCQL query
language and of the Android Credential Manager matcher ABI. It is licensed
BSD-2-Clause.

The OpenWallet Foundation's [Multipaz](https://github.com/openwallet-foundation-labs/multipaz)
project ships an Apache-2.0 credential matcher that solves the same problem
(`multipaz-dcapi/src/androidMain/matcher/`). We use it as a **conformance
oracle** and nothing else.

This is not a formal clean-room procedure. Clean-room exists for
reverse-engineering undocumented interfaces, and nothing here is undocumented —
DCQL is a public specification and the matcher ABI is an interoperability
interface. What follows is the narrower rule that BSD-2 licensing actually
requires: no Apache-2.0 *expression* enters this codebase.

Two implementations of DCQL will converge on **behaviour**, because the
specification dictates it. That convergence is expected and fine. What must not
converge is **expression**: file decomposition, type structure, algorithm shape
carried over line by line, or comments.

### You may

- Use the host ABI — function names, signatures, module names, calling
  conventions. It is an interface required for interoperability, and we hold it
  independently: it was extracted from the shipping `.wasm` binary's import and
  export tables before their header was ever opened.
- Run Multipaz's matcher binary and compare its output against ours.
- Commit behaviour observed that way as test vectors. A vector describing what a
  program does is a fact about it.
- Consult their source to answer "what does the host actually accept here?" when
  the specification is silent. Write the *fact* down, in your own words, in the
  code comment — never the passage that revealed it.

### You may not

- Copy or transliterate their source into Rust, in whole or in part. This
  applies with full force to `dcql.cpp`, `CredentialDatabase.cpp` and
  `Request.cpp`, which cover exactly the ground our core crates cover.
- Port their file or type decomposition structurally. This is the same problem
  as copying, and considerably harder to catch in review.
- Copy their comments, or adopt their identifier set wholesale.
- Vendor their binaries into this repository. Redistributing an Apache-2.0
  artifact from a BSD-2 tree drags in notice obligations for no benefit — the
  differential tests fetch the oracle at test time from a pinned upstream
  commit, or read it from a local checkout via `MULTIPAZ_MATCHER_WASM`, and skip
  when it is absent.

### Cite the spec, not the implementation

Every non-obvious matching rule carries a doc comment naming the section it
comes from — `OpenID4VP 1.0 §6.4.2`, `ISO/IEC 18013-7`, `W3C Digital
Credentials API`. A rule you cannot cite is a rule you should not be writing
yet: either it belongs to the configurable match profile rather than the engine,
or you have not finished reading.

Reviewers: treat an uncited behavioural rule as a review comment, and a
structural resemblance to the oracle as a blocker.

## Development

```sh
cargo test                      # everything, host targets
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo build -p siros-dc-matcher-wasm --target wasm32-wasip1 --release
```

`siros-dcql` is published to crates.io and therefore may not depend on any other
crate in this workspace. CI enforces this with `cargo publish --dry-run`; please
do not work around it.

## Pull requests

Branch from `main`, open a PR, keep the history linear. Every PR must be green on
CI — including the WASM size gate, which fails the build when `matcher.wasm`
grows past its budget. If your change legitimately needs the extra bytes, raise
the budget in the same PR and say why in the commit message.
