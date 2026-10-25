# android-credman-sys

Raw imports of the Android Credential Manager matcher host ABI: the functions
a WebAssembly matcher calls to read the request and the registered blob and
to offer entries in the credential picker.

All 22 functions of Google's reference header
(`digitalcredentialsdev/CMWallet` `matcher/credentialmanager.h` at
`abcf38a3`) are declared under their exact import module and name, with the
header's C types, together with the `CallingAppInfo` layout.

[`ABI.md`](ABI.md) is the contract: for every parameter, whether NULL is
accepted and what it means, how lengths work, and which host version
guarantees each function, with the evidence for each rule and the device
experiments that would settle what remains open.

## Modules and features

| Import module | Host level | Feature |
|---|---|---|
| `credman` | every host | always |
| `credman_v2` | 2 (`AddPaymentEntryToSetV2`: 3) | `v2` (`v3`) |
| `credman_v4` | 4 | `v4` |
| `credman_v5` | 5 | `v5` |
| `credman_v6` | 6 | `v6` |
| `credman_v7` | 7 | `v7` |

The functions exist on `wasm32` only. A binary imports exactly the functions
it calls; a feature makes a level's functions declarable.

## Use

These are `unsafe` raw imports. The `android-credman` crate states the
contract in types and gates each level on the version the host reports;
prefer it.

## Provenance

The declarations restate the interface of the reference header (module and
function names, parameter order and C types), which a matcher must match to
link. The documentation is written for this crate. `ABI.md` cites the header
and other sources by location.

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
