# android-credman-sys

Raw FFI bindings for the Android Credential Manager matcher ABI.

## Purpose

This crate mirrors the host-imported C ABI used by CMWallet matchers
(`matcher/credentialmanager.h`) with Rust `extern "C"` declarations.

Use this crate when you need exact symbol-level parity.

## How To Use

- Read verifier request bytes via `credman::GetRequestSize` and `credman::GetRequestBuffer`.
- Read credential blob bytes via `credman::GetCredentialsSize` and `credman::ReadCredentialsBuffer`.
- Emit standalone entries through `credman::*` functions.
- Emit grouped/set entries through `credman_v2::*` functions.
- Use `credman_v4::SelfDeclarePackageInfo` only for privileged/system scenarios.

## Pointer and String Conventions

- Text parameters are UTF-8 C strings (`*const c_char`) and are typically nullable.
- Binary payloads use `(ptr, len)` pairs where `ptr` may be null if `len == 0`.
- `set_index` is 0-based for all set APIs.

## Safety

These are raw host imports. Callers must uphold pointer validity and lifetime rules.
Prefer the higher-level `android-credman` crate unless you need direct ABI control.

