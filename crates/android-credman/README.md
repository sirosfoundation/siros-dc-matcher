# android-credman

Typed, version-gated access to the Android Credential Manager matcher host
ABI, over the raw imports of `android-credman-sys`.

The contract, with its evidence, is
[`android-credman-sys/ABI.md`](../android-credman-sys/ABI.md). This crate
states it in types:

- **Nullability.** A string the host needs is a `&C8Str` (UTF-8 and
  NUL-terminated at once, from the `c8str` crate); one it accepts as absent is
  an `Option<&C8Str>`, sent as NULL. A required image is a `&[u8]`; an optional
  one is an `Option<&[u8]>`, sent as NULL with length 0.
- **Version gating.** `Host::connect()` reads `GetWasmVersion` once. Its
  `WasmVersion` hands out one token per level (`V2` … `V7`). The level-2 token
  emits entry sets; the level-4 token declares package info; the tokens of
  levels 3, 5, 6 and 7 unlock the matching parts of a `SetEntry`. A call above
  the base level is unreachable without its token.
- **Imports.** A Cargo feature per level (`v2` … `v7`) declares that level's
  functions. The entry kind of a set is a type parameter, so a matcher that
  only offers credentials imports `AddEntryToSet` and none of the payment
  functions.
- **Set shape.** An `EntrySet` has at least one slot and every slot at least
  one entry; positions and the declared length follow from the slots, and
  fields and decorations belong to their entry. Two rules stay with the
  caller: a set id is declared once per invocation, and the alternatives of
  one slot have distinct ids.
- **No panics.** The crate holds no `unwrap`, `expect` or `panic!`.

```rust,ignore
use android_credman::{C8Str, EntrySet, Host, SetEntry, SetSink, Slot, VerificationDisplay};

let host = Host::connect();
let Some(mut sets) = host.version().v2() else { return };   // entry sets need level 2
let request = host.request();
let blob = host.credentials();

let title = C8Str::from_str_with_nul("Driving Licence\0")?;
let entry = SetEntry::new(cred_id, VerificationDisplay {
    icon: png_bytes,
    title,
    subtitle: None,
    disclaimer: None,
    warning: None,
})
.with_metadata(metadata);
sets.add_entry_set(&EntrySet::new(set_id, Slot::one(&entry), &[]));
```

`Host` and the emitters exist on `wasm32` only. The data types compile
everywhere, and `SetSink` lets a test stand in for the host.

## Features

| Feature | Default | Enables |
|---|---|---|
| `std` | yes | `CredentialReader`, a `std::io::Read + Seek` view of the registered blob |
| `v2` | | entry sets (`credman_v2`) |
| `v3` | | `PaymentWithInfo` (`AddPaymentEntryToSetV2`) |
| `v4` | | `V4::self_declare_package_info` |
| `v5` | | `SetEntry::with_metadata_display_text` |
| `v6` | | `SetEntry::with_link` |
| `v7` | | `SetEntry::with_delegation` |

## Licence

MIT OR Apache-2.0, at your option. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
