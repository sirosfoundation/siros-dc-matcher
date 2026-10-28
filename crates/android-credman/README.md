# android-credman

The Android Credential Manager matcher host ABI as types, over
`android-credman-sys`. The rules come from
[`ABI.md`](../android-credman-sys/ABI.md).

```rust,ignore
let host = Host::connect_with(HostOptions {
    package_info: None,
    delegation: Some(DelegationType::Full),
});
let Some(mut sets) = host.entry_sets() else { return };
let request = host.request();
let mut registration = CredentialReader::new(host);

let entry = SetEntry::new(cred_id, VerificationDisplay {
    icon,
    title,
    subtitle: None,
    disclaimer: None,
    warning: None,
})
.with_data(json)
.with_fields(fields)
.with_metadata_display_text(text);
sets.add_entry_set(&EntrySet::new(set_id, Slot::one(&entry), &[]));
```

- `CredentialReader` reads the blob the wallet registered as `Read` and
  `Seek`, each read one `ReadCredentialsBuffer` call at an offset.
- `V1` to `V7` give each host level's functions as safe calls.
  `host.credman()` hands out the base, `Credman`; `version::<Credman5>()`
  grants level 5's singleton when the host reports level 5. Every call is
  static, so a binary imports only what it calls.
- `host.entry_sets()` exists from level 2. Each entry option is sent from its
  level: payment information from 3, display text from 5, a link from 6, a
  delegation from 7 (the entry's own, else the host default).
- Every set entry carries the standard metadata object
  `{"display_skipped":bool,"host_level":n,"data":…}`, which the wallet
  receives on selection and reads with `Picked::parse`. `display_skipped` is
  true when the entry carries text the host level does not show; `data` is the
  caller's JSON.
- `None` reaches the host as NULL and hides the element; `Some` of an empty
  string shows it blank.
- The caller keeps two set rules: declare a set id once per invocation, and
  give the alternatives of one slot distinct ids.
- `C8StringExt` builds host strings without failing: a NUL becomes a space.
- `Host` and the level traits exist on `wasm32` only. Implement `SetSink` to
  test a matcher elsewhere.
- Raw pointers exist only inside the `unsafe` calls into
  `android-credman-sys`; every type here is safe Rust.
