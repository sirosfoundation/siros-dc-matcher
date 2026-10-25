# android-credman

The Android Credential Manager matcher host ABI as types, over
`android-credman-sys`. The rules come from
[`ABI.md`](../android-credman-sys/ABI.md).

```rust,ignore
let host = Host::connect();
let Some(mut sets) = host.version().v2() else { return };
let request = host.request();
let blob = host.credentials();

let entry = SetEntry::new(cred_id, VerificationDisplay {
    icon,
    title,
    subtitle: None,
    disclaimer: None,
    warning: None,
})
.with_metadata(metadata);
sets.add_entry_set(&EntrySet::new(set_id, Slot::one(&entry), &[]));
```

- `None` reaches the host as NULL and hides the element; `Some` of an empty
  string shows it blank.
- A call above the base level needs its level's token from
  `host.version()`.
- The caller keeps two set rules: declare a set id once per invocation, and
  give the alternatives of one slot distinct ids.
- `Host` exists on `wasm32` only. Implement `SetSink` to test a matcher
  elsewhere.

## Features

| Feature | Default | Enables |
|---|---|---|
| `std` | yes | `CredentialReader` |
| `v2` | | `V2`: entry sets |
| `v3` | | `V3`: `PaymentWithInfo` |
| `v4` | | `V4::self_declare_package_info` |
| `v5` | | `SetEntry::with_metadata_display_text` |
| `v6` | | `SetEntry::with_link` |
| `v7` | | `SetEntry::with_delegation` |
