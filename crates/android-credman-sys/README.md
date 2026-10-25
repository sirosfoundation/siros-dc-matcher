# android-credman-sys

Raw imports of the Android Credential Manager matcher host ABI, following
Google's `matcher/credentialmanager.h` at CMWallet `abcf38a3`.
[`ABI.md`](ABI.md) gives each parameter's NULL and length rule, each
function's host level, and the evidence.

Use [`android-credman`](../android-credman).

Modules `credman` and `v2` … `v7` group the functions by host level and exist
on `wasm32` only. `v3::AddPaymentEntryToSetV2` is imported from `credman_v2`,
where Google's header declares it.
