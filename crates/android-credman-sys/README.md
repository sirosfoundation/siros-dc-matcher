# android-credman-sys

Raw imports of the Android Credential Manager matcher host ABI, following
Google's `matcher/credentialmanager.h` at CMWallet `abcf38a3`.
[`ABI.md`](ABI.md) gives each parameter's NULL and length rule, each
function's host level, and the evidence.

Use [`android-credman`](../android-credman).

## Features

One per host level. The functions exist on `wasm32` only.

| Feature | Declares |
|---|---|
| none | `credman` |
| `v2` | `credman_v2` |
| `v3` | `AddPaymentEntryToSetV2`, from `credman_v2`, where Google's header declares this level-3 function |
| `v4` … `v7` | `credman_v4` … `credman_v7` |
