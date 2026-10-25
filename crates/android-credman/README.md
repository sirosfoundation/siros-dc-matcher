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
  `host.version()`. `WithDelegation`, `WithLink` and
  `WithMetadataDisplayText` wrap an entry kind to add the level-7, 6 and 5
  calls.
- The caller keeps two set rules: declare a set id once per invocation, and
  give the alternatives of one slot distinct ids.
- `Host` exists on `wasm32` only. Implement `SetSink` to test a matcher
  elsewhere.
