# android-credman

High-level Rust bindings for Android Credential Manager matcher hosts.

## Purpose

This crate provides ergonomic, mostly borrowed-data APIs over the raw matcher ABI.

Use it to:
- read verifier request and credential input streams,
- build credential rows and groups in Rust structs,
- emit results through a version-aware host facade (`credman`).

## API Layers

- `input::*`: request and credential blob readers.
- `structs::*`: presentation rows (`StringIdEntry`, `PaymentEntry`, `CredentialSet`, ...).
- `host::*`: explicit version-aware host traits (`Credman`, `CredmanV2+`).
- `traits::*`: glue traits for matcher entrypoints (`CredmanApply`, `FromRequest`, `FromCredentials`).

