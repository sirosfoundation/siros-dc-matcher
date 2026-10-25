# Credential Manager matcher ABI

Every host function's signature, its parameters' NULL and length rules, and
the host level that guarantees it. The host is closed source: each rule is
inferred, and its Evidence column gives the strength.

## Contents

1. [Sources](#sources)
2. [Conventions](#conventions)
3. [Versions and linking](#versions)
4. [Functions](#functions)
5. [Parameters](#parameters)
6. [Entry sets](#sets)
7. [Conflicts between sources](#conflicts)
8. [Rules left conservative](#conservative)
9. [Device experiments](#experiments)

<a id="sources"></a>
## 1. Sources

| Key | Source | Revision | Weight |
|---|---|---|---|
| **H** | Google's reference header [`matcher/credentialmanager.h`][H] | CMWallet `abcf38a3` (2026-10-02), identical to `4230483c` | Interface: module, name, C types. Two comments; no rules |
| **HH** | The header's history, 14 commits from [`28d55e39`][HH-first] to [`4230483c`][HH-v7] | as listed in §3 | Dates each function |
| **GC** | Google's OpenID4VP C matcher [`matcher/openid4vp1_0.c`][GC] | CMWallet `abcf38a3` | What Google passes, and its version checks |
| **GP** | Google's phone-number-verification C matcher [`matcher/pnv/openid4vp1_0.c`][GP] | CMWallet `abcf38a3` | The only caller of levels 6 and 7 |
| **GR** | Google's Rust matcher [`matcher-rs/src`][GR] (`bindings.rs`, `credman.rs`, `reporter.rs`) | CMWallet `abcf38a3` | What Google passes; module placement is wrong (§7) |
| **GA** | Google's shipped matcher binaries [`app/src/main/assets/*.wasm`][GA] | CMWallet `abcf38a3` | Their import tables, read with a parser |
| **GT** | Google's host fake [`matcher/test_runner.cc`][GT] and [`matcher/test_plan.md`][GT-plan], written "based on the real Android Credential Manager's host implementation (`RegistryRuntime.kt`)" | CMWallet `abcf38a3` | How Google models the host's bookkeeping |
| **AX** | androidx registry types: [`VerificationEntryDisplayProperties.kt`][AX-entry], [`VerificationFieldDisplayProperties.kt`][AX-field], [`InlineIssuanceEntry.kt`][AX-inline], [`DelegationType.kt`][AX-deleg], [`RegisterCredentialsRequest.kt`][AX-req], [`ProviderGetCredentialRequest.kt`][AX-select] | androidx `2b7ce630` | The registry side of the same display data, and what the wallet receives on selection |
| **MP** | OpenWallet Foundation Multipaz C++ matcher [`CredentialDatabase.cpp`][MP] | multipaz `5c15239f` | A production matcher's calls |
| **SD** | Device findings of this repository: [`docs/abi.md`][SD-doc] lines 31–50, commits [`3d61ac7`][SD-icon] and [`6cd02c9`][SD-badge] | siros-dc-matcher `ac573c2` | Observed on a Pixel through logcat and the share sheet |
| **EP** | Elpaso wallet [patch 0003][EP] on Google's C matcher | elpaso `4f89c660` | Observed on a device |
| **SP** | Sphereon matcher [`matcher-build/src/lib.rs`][SP] | mobile-wallet `19bcf497` | A third-party matcher's calls |
| **SR** | This repository's released `matcher.wasm`, [v0.8.0][SR] to v0.11.0, which import `wasi_snapshot_preview1.random_get` (read with a parser), and the repository owner's device report on them | releases 2026-10-14 to 2026-10-20 | Observed on a device: they load, and the host lacks `random_get` |

Also searched, without a rule found: the
[Android holder guide](https://developer.android.com/identity/digital-credentials/credential-holder)
and CMWallet's issues, where
[#10](https://github.com/digitalcredentialsdev/CMWallet/issues/10) reports
"No ID Found" on some Android 11 devices, undiagnosed.

<a id="conventions"></a>
## 2. Conventions

| Topic | Rule | Evidence |
|---|---|---|
| Integer widths on `wasm32` | Pointers, `size_t`, `int` and `uint32_t*` are `i32`; `long long` is `i64`. | H; GA import tables (`AddEntry`'s first parameter is the only `i64`) |
| Strings | NUL-terminated. Read as UTF-8 by the host. | H (`const char*`); AX types are `CharSequence`, filled from UTF-8 JSON by GC and MP. UTF-8 is unconfirmed: conservative |
| NULL for a string | Accepted only where §5 says so; it means "absent" and the host omits the element. | §5 per parameter |
| Empty string versus NULL | Different. An empty `disclaimer` or `warning` is a present, blank element: the picker draws the badge or note with nothing in it. NULL draws nothing. | SD [`6cd02c9`][SD-badge]: every entry carried a warning triangle while these were `""`; NULL removed it. GR maps an empty Rust string to NULL for every optional string ([`credman.rs`][GR-credman] lines 108–411) |
| Images | A pointer and a byte length. An optional image is absent as NULL with length 0. | GC passes `NULL, 0` for the bank and provider icons ([lines 91–106][GC-pay]) and `0, 0` for an inline-issuance entry without icon ([lines 387–388][GC-inline]) |
| A NULL image with a non-zero length | Outside the contract. | Unconfirmed: conservative |
| Ownership | The host reads every argument during the call. The matcher may free or reuse its buffers when the call returns. | SD: this repository frees every string right after each call and saw correct titles, fields and disclaimers on a Pixel. A host that kept pointers into linear memory would read reused bytes |
| Out-pointers | Every `uint32_t*`, `void*` and `CallingAppInfo*` must be non-null and point to memory the matcher owns, large enough for what the host writes. Address 0 is valid linear memory in WebAssembly, so a NULL out-pointer makes the host write over the matcher's own data. | H; WebAssembly memory model. Conservative |
| Entry point | The host calls the export `_start` with no arguments and reads the export `memory`. | SD (`docs/abi.md` "Exports"); GR [`bin/presentation.rs`][GR-start] exports `_start` for `wasm32-unknown-unknown` "Credman expects this as the entry point" |
| WASI | The host provides at least `fd_write`, `fd_seek`, `fd_close`, `fd_fdstat_get` and `proc_exit` from `wasi_snapshot_preview1`. It lacks `random_get`, which std's default hasher reads. Anything else is unconfirmed. | GA: Google's shipped matchers import exactly these five. SD: a shipping binary's table showed the same subset. SR: the host lacks `random_get`; a third-party README reports the same (cited in `docs/abi.md` line 18) |
| A failing matcher | A matcher that fails to load or traps shows the user nothing. | AX [`RegisterCredentialsRequest.kt`][AX-req] lines 27–31: "an invalid matcher (e.g. one that fails wasm interpretation or causes exceptions) will mean that your credentials will never be surfaced" |

<a id="versions"></a>
## 3. Versions and linking

### Levels

Module `credman_vN` holds the functions of level N, with one exception:
Google's header declares the level-3 function, `AddPaymentEntryToSetV2`, in
`credman_v2`, and no `credman_v3` module exists in any revision.
`android-credman-sys` groups it with level 3 and imports it from
`credman_v2`.

| Level | Guarantees | Added to the header | Evidence for the threshold |
|---|---|---|---|
| any | `credman`: inputs, `GetWasmVersion`, the standalone entries | 2024-10-23 [`28d55e39`][HH-first]; `AddPaymentEntry` 2024-11-07 [`808b9246`][HH-pay]; `SetAdditionalDisclaimerAndUrlForVerificationEntry` 2025-05-16 [`a2094a72`][HH-link]; `AddInlineIssuanceEntry` 2025-06-23 [`e2c681bb`][HH-inline]; `GetWasmVersion` 2025-08-12 [`ef2efeea`][HH-v2] | GC calls the standalone functions when the level is 1 or lower ([lines 99–107, 137–165][GC-v1]) |
| 2 | `credman_v2`: `AddEntrySet`, `AddEntryToSet`, `AddFieldToEntrySet`, `AddPaymentEntryToSet` | 2025-08-12 [`ef2efeea`][HH-v2] | GC `wasm_version > 1` ([line 132][GC-v2]), `== 2` for `AddPaymentEntryToSet` ([line 95][GC-pay]); MP `>= 2` ([line 388][MP]); GR `> 1` ([`reporter.rs` line 323][GR-reporter]) |
| 3 | `credman_v2.AddPaymentEntryToSetV2` | 2025-09-15 [`d17ac461`][HH-v3] | GC `wasm_version >= 3` ([line 91][GC-pay]); GT plan TC36 "Mock WASM version 3 (payment)" |
| 4 | `credman_v4.SelfDeclarePackageInfo` | 2025-09-24 [`187c8923`][HH-v4] | Module name only: no matcher calls it |
| 5 | `credman_v5.AddMetadataDisplayTextToEntrySet` | 2026-02-26 [`72b265b7`][HH-v5] | GC `wasm_version >= 5` ([line 167][GC-v5]); GR `>= 5` ([`reporter.rs` line 116][GR-reporter]) |
| 6 | `credman_v6.SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet` | 2026-03-02 [`98e6c9c9`][HH-v6] | Module name. GP calls it with no level check (§7) |
| 7 | `credman_v7.SetDelegationTypeForEntryInSet` | 2026-09-17 [`4230483c`][HH-v7] | GP `wasm_version >= 7` ([lines 249–251][GP-v7]) |

The `credman` functions added after the first header revision have dates
and no level in any source; they stay with `credman`. No source
distinguishes level 0 from level 1.

`GetWasmVersion` entered the header with `credman_v2`, so a host without
`credman_v2` may lack it too. Every version-aware matcher calls it first (GC
[line 425][GC-ver], GP [line 333][GP-ver], MP [line 382][MP], GR
[`reporter.rs` line 285][GR-reporter]).

### Linking

The host links a module whose imports it lacks; the call traps.

- SR: releases v0.8.0 to v0.11.0 import `random_get`, which the host lacks.
  They load on a device and trap on a `zkp_req` request, whose planner
  builds a std `HashSet`.
- GA, GC, GP: Google's binaries import `credman_v5`, `credman_v6` and
  `credman_v7` and check `GetWasmVersion` before calling them (GC
  [lines 132–169][GC-v2]). That works only if a missing import is harmless
  until called. MP does the same for `credman_v2`.

`android-credman` hands out the base level and grants each higher level's
singleton only after checking the reported level. Its calls are static, so
a binary imports only the functions it calls.
`scripts/check_matcher_abi.py` reports the highest level a binary imports.
Device experiment 1 confirms lazy resolution for a `credman` module.

<a id="functions"></a>
## 4. Functions

Line numbers refer to [the header][H]. `scripts/check_matcher_abi.py`
checks the same WebAssembly signatures.

| # | Function | Module | Level | C signature | WebAssembly signature | Header lines |
|---|---|---|---|---|---|---|
| 1 | `AddEntry` | `credman` | any | `void (long long cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning)` | `(i64 i32 i32 i32 i32 i32 i32) -> ()` | 11–15 |
| 2 | `AddField` | `credman` | any | `void (long long cred_id, const char* field_display_name, const char* field_display_value)` | `(i64 i32 i32) -> ()` | 17–21 |
| 3 | `AddEntrySet` | `credman_v2` | 2 | `void (const char* set_id, int set_length)` | `(i32 i32) -> ()` | 23–26 |
| 4 | `AddEntryToSet` | `credman_v2` | 2 | `void (const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning, const char* metadata, const char* set_id, int set_index)` | `(i32 ×10) -> ()` | 28–31 |
| 5 | `AddFieldToEntrySet` | `credman_v2` | 2 | `void (const char* cred_id, const char* field_display_name, const char* field_display_value, const char* set_id, int set_index)` | `(i32 ×5) -> ()` | 33–36 |
| 6 | `AddPaymentEntryToSet` | `credman_v2` | 2 | `void (const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len, const char* metadata, const char* set_id, int set_index)` | `(i32 ×14) -> ()` | 38–41 |
| 7 | `AddPaymentEntryToSetV2` | `credman_v2` | 3 | as 6, with `const char* additional_info` before `metadata` | `(i32 ×15) -> ()` | 43–46 |
| 8 | `AddStringIdEntry` | `credman` | any | `void (const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle, const char* disclaimer, const char* warning)` | `(i32 ×7) -> ()` | 48–51 |
| 9 | `AddFieldForStringIdEntry` | `credman` | any | `void (const char* cred_id, const char* field_display_name, const char* field_display_value)` | `(i32 ×3) -> ()` | 53–56 |
| 10 | `GetRequestBuffer` | `credman` | any | `void (void* buffer)` | `(i32) -> ()` | 58–64 |
| 11 | `GetRequestSize` | `credman` | any | `void (uint32_t* size)` | `(i32) -> ()` | 66–69 |
| 12 | `ReadCredentialsBuffer` | `credman` | any | `size_t (void* buffer, size_t offset, size_t len)` | `(i32 i32 i32) -> (i32)` | 71–74 |
| 13 | `GetCredentialsSize` | `credman` | any | `void (uint32_t* size)` | `(i32) -> ()` | 76–79 |
| 14 | `GetWasmVersion` | `credman` | any (§3) | `void (uint32_t* version)` | `(i32) -> ()` | 81–84 |
| 15 | `AddPaymentEntry` | `credman` | any | `void (const char* cred_id, const char* merchant_name, const char* payment_method_name, const char* payment_method_subtitle, const char* payment_method_icon, size_t payment_method_icon_len, const char* transaction_amount, const char* bank_icon, size_t bank_icon_len, const char* payment_provider_icon, size_t payment_provider_icon_len)` | `(i32 ×11) -> ()` | 86–89 |
| 16 | `AddInlineIssuanceEntry` | `credman` | any | `void (const char* cred_id, const char* icon, size_t icon_len, const char* title, const char* subtitle)` | `(i32 ×5) -> ()` | 91–94 |
| 17 | `SetAdditionalDisclaimerAndUrlForVerificationEntry` | `credman` | any | `void (const char* cred_id, const char* secondary_disclaimer, const char* url_display_text, const char* url_value)` | `(i32 ×4) -> ()` | 96–99 |
| 18 | `SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet` | `credman_v6` | 6 | `void (const char* cred_id, const char* secondary_disclaimer, const char* url_display_text, const char* url_value, const char* set_id, int set_index)` | `(i32 ×6) -> ()` | 101–104 |
| 19 | `GetCallingAppInfo` | `credman` | any | `void (CallingAppInfo* info)` with `struct { char package_name[256]; char origin[512]; }` | `(i32) -> ()` | 106–114 |
| 20 | `SelfDeclarePackageInfo` | `credman_v4` | 4 | `void (const char* package_display_name, const char* package_icon, size_t package_icon_len)`; the header notes it works for system applications only | `(i32 ×3) -> ()` | 117–121 |
| 21 | `AddMetadataDisplayTextToEntrySet` | `credman_v5` | 5 | `void (const char* cred_id, const char* metadata_display_text, const char* set_id, int set_index)` | `(i32 ×4) -> ()` | 123–126 |
| 22 | `SetDelegationTypeForEntryInSet` | `credman_v7` | 7 | `void (const char* cred_id, int delegation_type, const char* set_id, int set_index)` | `(i32 ×4) -> ()` | 128–131 |

<a id="parameters"></a>
## 5. Parameters

*Required*: non-null; a string is NUL-terminated UTF-8, an image has length
≥ 1. *Nullable*: NULL means absent, with length 0 for an image.
*Conservative*: no source settles the rule; the stricter choice stands.

### Standalone entries (`credman`)

| Function | Parameter | Rule | Empty value | Evidence |
|---|---|---|---|---|
| `AddStringIdEntry` | `cred_id` | required | unconfirmed | GC, GR, MP, SP all pass a string. Fields attach by it, so it is unique among standalone entries (GT keys entries by id). AX returns it to the wallet as `selectedEntryId` ([lines 29–42][AX-select]) |
| | `icon`, `icon_len` | required | an empty image is treated as no image | Conservative. SD shows NULL drops an `AddEntryToSet` entry; AX types the registry icon non-null ([lines 45–47][AX-entry]). SP passes NULL here; GC passes the blob pointer with length 0 when its registry has no icon |
| | `title` | required | unconfirmed | AX `title: CharSequence` non-null ([line 45][AX-entry]). GR passes NULL for an empty title (§7) |
| | `subtitle` | nullable | unconfirmed | AX `subtitle: CharSequence?` ([line 46][AX-entry]); GC passes an absent registry value as NULL ([line 115][GC-v1]); GR NULL when empty |
| | `disclaimer` | nullable | drawn as a blank note | GC passes NULL ([line 144][GC-v1]); MP NULL ([line 426][MP]); SP NULL. AX `explainer` "if set" ([lines 26–28, 48][AX-entry]); SD for the empty string |
| | `warning` | nullable | drawn as a blank badge | As `disclaimer`; AX `warning` "if set" ([lines 29–31, 49][AX-entry]) |
| `AddFieldForStringIdEntry` | `cred_id` | required; names an entry added by `AddStringIdEntry` | — | GC, MP |
| | `field_display_name` | required | unconfirmed | AX `displayName` must not be blank ([lines 34–38][AX-field]) |
| | `field_display_value` | nullable: the name is shown alone | unconfirmed | AX "a null value means only the display name will be rendered" ([lines 27–29][AX-field]); MP passes NULL for an omitted value ([line 435][MP]); GC passes an absent value as NULL ([line 151][GC-v1]) |
| `AddEntry` | `cred_id` (`i64`) | any value | — | H |
| | `icon`, `title`, `subtitle`, `disclaimer`, `warning` | all required | — | Conservative: no matcher calls it. H marks it superseded by `AddStringIdEntry` (line 11) |
| `AddField` | `cred_id` (`i64`), `field_display_name`, `field_display_value` | strings required | — | Conservative: no matcher calls it (H line 17) |
| `AddPaymentEntry` | `cred_id` | required | — | GC |
| | `merchant_name` | required | — | EP: a payment entry with NULL merchant and amount "is then never shown" |
| | `payment_method_name` | required | — | Conservative. GC passes the registry title, which AX makes non-null; GR passes NULL when empty |
| | `payment_method_subtitle` | nullable | — | GC passes the registry subtitle, nullable in AX |
| | `payment_method_icon`, `_len` | required | — | Conservative. GC passes the registry icon, non-null in AX |
| | `transaction_amount` | required | — | EP, as `merchant_name` |
| | `bank_icon`, `_len` | nullable | — | GC passes `NULL, 0` on every payment entry ([lines 91–106][GC-pay]) |
| | `payment_provider_icon`, `_len` | nullable | — | As `bank_icon` |
| `AddInlineIssuanceEntry` | `cred_id` | required | — | GC, GR |
| | `icon`, `icon_len` | nullable: the host shows the app's icon | — | GC `0, 0` without icon ([line 388][GC-inline]); AX `iconHint: Bitmap?`, shown for privileged apps only ([lines 54–61][AX-inline]) |
| | `title` | nullable: the host shows the app's label | — | AX `titleHint: CharSequence?`, "most applications should leave this unset" ([lines 51–60][AX-inline]); GC passes an absent value as NULL ([line 384][GC-inline]) |
| | `subtitle` | nullable | — | AX `subtitle: CharSequence?` ([line 59][AX-inline]) |
| `SetAdditionalDisclaimerAndUrlForVerificationEntry` | `cred_id` | required; names an `AddStringIdEntry` entry | — | H |
| | `secondary_disclaimer`, `url_display_text`, `url_value` | required | — | Conservative: no matcher calls it |

### Inputs (`credman`)

| Function | Parameter | Rule | Evidence |
|---|---|---|---|
| `GetRequestSize` | `size` | required out-pointer; receives the request length in bytes | H; GC [lines 19–20][GC-in] |
| `GetRequestBuffer` | `buffer` | required; holds the length `GetRequestSize` reported. The host writes exactly that many bytes and no terminator | GT fake copies `size()` bytes ([`test_runner.cc` lines 141–143][GT]); GC mallocs exactly the size and parses it as a C string, which reads past the end (a GC defect) |
| `GetCredentialsSize` | `size` | required out-pointer; receives the blob length | H |
| `ReadCredentialsBuffer` | `buffer` | required; holds `len` bytes | H |
| | `offset` | byte offset into the blob | H |
| | `len` | bytes asked for | H |
| | return | bytes copied; may be less than `len`. A matcher keeps reading until it has the whole blob | GT fake returns `min(len, size − offset)` and 0 past the end ([lines 149–153][GT]) |
| `GetWasmVersion` | `version` | required out-pointer | H |
| `GetCallingAppInfo` | `info` | required; a whole 768-byte struct. Each field is NUL-terminated when shorter than the field. A field the host fills to the brim has no terminator, and the bytes are expected to be UTF-8; a matcher reads each field inside its buffer and treats a missing NUL or invalid UTF-8 as an error. An array field cannot be NULL, so an empty `origin` stands for none | H (layout); field encoding unconfirmed: conservative |

### Entry sets (`credman_v2`, levels 2 and 3)

| Function | Parameter | Rule | Empty value | Evidence |
|---|---|---|---|---|
| `AddEntrySet` | `set_id` | required; unique within the invocation | unconfirmed | SD: declaring an id twice discards the whole output. GR builds a distinct id per combination ([`reporter.rs` lines 296–325][GR-reporter]). GC repeats ids (§7). AX returns it to the wallet as `credentialSetId` ([lines 44–64][AX-select]) |
| | `set_length` | ≥ 1: the number of positions | — | GC, GR, MP pass the number of slots. 0 is conservative-forbidden |
| `AddEntryToSet` | `cred_id` | required; distinct among the alternatives of one position | — | GT keys entries by position, then id ([`test_runner.cc` lines 161–171][GT]). AX returns it to the wallet as `credentialId` ([lines 87–95][AX-select]) |
| | `icon`, `icon_len` | required: the host drops an entry without an icon. A 64×64 PNG shows; a 4×4 PNG was dropped | — | **SD device**: "`WasmRuntime: Null icon for icon`" and no entry; the PNG sizes ([`docs/abi.md` lines 36–42][SD-doc]) |
| | `title` | required | unconfirmed | AX non-null; GR NULL when empty (§7) |
| | `subtitle` | nullable | unconfirmed | AX nullable; GR NULL when empty |
| | `disclaimer` | nullable | drawn as a blank note | **SD device** ([`6cd02c9`][SD-badge]); GC passes an absent `explainer` as NULL ([line 135][GC-v2]); MP NULL ([line 413][MP]) |
| | `warning` | nullable | drawn as a blank badge | **SD device**; GC NULL ([line 135][GC-v2]); MP NULL ([line 414][MP]) |
| | `metadata` | nullable | unconfirmed | MP passes NULL on every entry ([line 415][MP]); GR NULL when empty. Returned to the wallet on selection (AX `SelectedCredential.metadata`, [lines 87–95][AX-select]) |
| | `set_id` | required; declared earlier by `AddEntrySet` | — | GC, GR, MP declare first |
| | `set_index` | 0 ≤ `set_index` < `set_length` | — | GC, GR, MP number positions from 0 |
| `AddFieldToEntrySet` | `cred_id`, `set_id`, `set_index` | required; name an entry added earlier | — | GT appends to the entry at that position and id ([lines 173–179][GT]); this repository's test host refuses a mismatch |
| | `field_display_name` | required | unconfirmed | AX non-blank |
| | `field_display_value` | nullable: the name is shown alone | unconfirmed | GP passes NULL on every field ([line 272][GP-fields]); MP NULL for an omitted value; AX |
| `AddPaymentEntryToSet` | as `AddPaymentEntry`, plus `metadata`, `set_id`, `set_index` as `AddEntryToSet` | | | GC [line 97][GC-pay] |
| `AddPaymentEntryToSetV2` | as `AddPaymentEntryToSet`, plus `additional_info` | nullable | unconfirmed | GC passes an absent value as NULL ([lines 306–320][GC-txn]); GR NULL when empty |

### Levels 4 to 7

| Function | Parameter | Rule | Evidence |
|---|---|---|---|
| `SelfDeclarePackageInfo` | `package_display_name` | required | Conservative: no matcher calls it |
| | `package_icon`, `_len` | required | Conservative |
| `AddMetadataDisplayTextToEntrySet` | `cred_id`, `set_id`, `set_index` | required; name an entry added earlier | GC, GR call it after the entry's fields |
| | `metadata_display_text` | required | GC calls it only when the text is non-NULL ([line 167][GC-v5]); GR only when non-empty ([`reporter.rs` lines 116–118][GR-reporter]) |
| `SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet` | `cred_id`, `set_id`, `set_index` | required; name an entry added earlier | GP |
| | `secondary_disclaimer`, `url_display_text`, `url_value` | required | Conservative. GP passes registry values that are NULL when absent ([lines 253–266][GP-link]) (§7) |
| `SetDelegationTypeForEntryInSet` | `cred_id`, `set_id`, `set_index` | required; name an entry added earlier | GP calls it right after the entry ([lines 244–251][GP-v7]) |
| | `delegation_type` | 0 (the wallet's UI) or 1 (Credential Manager drives, the wallet fulfils in the background) | AX `DelegationType.NONE = 0`, `FULL = 1` ([lines 49, 63][AX-deleg]); GP passes 1 |

<a id="sets"></a>
## 6. Entry sets

The user selects a set as a whole, and one alternative per position.

- `AddEntrySet(set_id, n)` declares positions `0 … n−1`: one per credential
  query of the chosen options (GC [lines 35–49][GC-len], GR
  [`reporter.rs` lines 296–325][GR-reporter]).
- The matches for a query are alternatives at the same position (GC
  [lines 52–56][GC-alt], MP [lines 393–452][MP]).
- Every position needs an entry. GP leaves positions empty only at level 7
  with every entry fully delegated ([lines 117–129][GP-partial]).
  `android-credman` builds full sets only.
- The host names an entry by `(set_id, set_index, cred_id)`; fields, metadata
  text, the level-6 link and the level-7 delegation use the same key (GT).
- A set id is declared once per invocation (SD; GC repeats ids, §7).
- Google's matchers send an entry, then its delegation and link, then its
  fields, then its metadata text (GP lines 244–272, GC lines 135–169).

<a id="conflicts"></a>
## 7. Conflicts between sources

| Question | One side | Other side | Resolution |
|---|---|---|---|
| Module of the set functions | H: `credman_v2`, `credman_v4` … `credman_v7`; GA's binaries import them there | GR declares all 22 functions in one `#[link(wasm_import_module = "credman")]` block ([`bindings.rs` line 9][GR-bindings]), plus `fd_write` in `credman` (line 143). Eight functions sit in the wrong module | H and GA win: they are what ships. GR's bindings are a defect; GR remains evidence for the values it passes |
| Version checks in GR | GC checks the level before every set call | GR calls `add_entry_to_set` ([`reporter.rs` line 70][GR-reporter]) and `add_payment_entry_to_set_v2` (line 31) with no level check; only `add_entry_set` is gated | GC's thresholds stand |
| A repeated set id | SD (device): a second `AddEntrySet` with the same id discards everything | GC's `report_credential_set_length` declares the same id once per combination of later options ([lines 35–49][GC-len]); GT's fake overwrites the set ([`test_runner.cc` lines 156–159][GT]) | SD is a device observation; GC's repetition only happens for queries with several credential sets. Rule: unique ids |
| Unfilled positions | This repository's matcher treats a gap as a matcher bug | GP leaves gaps on purpose | Both hold: gaps are a level-7 feature for fully delegated options (§6) |
| NULL `title` | AX types it non-null | GR passes NULL for an empty title | Required: AX is the product's own type and GR only does it for empty input |
| NULL for the level-6 link texts | No source for the standalone variant | GP passes possibly-NULL values with no level check | Required (conservative); device experiment 5 |
| Runtime version branches | `docs/abi.md`: a module that declares `credman_v2` cannot load on a host without it | GC, GP, MP branch at runtime inside one binary | SR's device evidence: an import the host lacks links and traps when called. The branches stand; device experiment 1 confirms it for a `credman` module |
| NULL icon on `AddStringIdEntry` | SD: NULL drops an `AddEntryToSet` entry | SP passes NULL on every entry | Required (conservative); device experiment 2 |

<a id="conservative"></a>
## 8. Rules left conservative

Set to the stricter choice:

- every pointer of `AddEntry`, `AddField`,
  `SetAdditionalDisclaimerAndUrlForVerificationEntry` and
  `SelfDeclarePackageInfo` (no caller anywhere);
- the image of `AddStringIdEntry`, `AddEntry`, the payment-method image of the
  payment functions, and `SelfDeclarePackageInfo`'s icon: required;
- `payment_method_name`: required;
- the three texts of the level-6 link: required;
- UTF-8 for every string, and for both `CallingAppInfo` fields;
- `set_length ≥ 1`, `0 ≤ set_index < set_length`, every position filled;
- a NULL image with a non-zero length, and an image pointer with length 0:
  outside the contract;
- `delegation_type` values other than 0 and 1.

<a id="experiments"></a>
## 9. Device experiments

Run on a current Pixel with `adb logcat | grep WasmRuntime` open.

1. **Lazy resolution for `credman`.** A matcher that imports
   `credman_v99.Nope (i32) -> ()` emits one entry set without calling it:
   does the entry show? Then call it after emitting: does the trap discard
   the entries?
2. **NULL icon on a standalone entry.** `AddStringIdEntry` with `icon = NULL,
   0` and with `icon = <blob>, 0`. Does the entry appear?
3. **NULL title.** `AddEntryToSet` with `title = NULL`. Entry dropped, empty
   title, or a host crash?
4. **NULL metadata and field value.** `AddEntryToSet` with `metadata = NULL`
   and `AddFieldToEntrySet` with `field_display_value = NULL`; select the
   entry and read what the wallet receives.
5. **Level-6 link with NULL texts.** On a level-6 host, each of the three
   texts NULL in turn.
6. **Repeated set id.** Two `AddEntrySet` calls with one id, as GC does for
   several credential sets: does the host discard everything, keep the
   second, or merge?
7. **Empty set and unfilled position.** `AddEntrySet(id, 0)`; and
   `AddEntrySet(id, 2)` with only position 0 filled, below level 7 and at
   level 7 with `SetDelegationTypeForEntryInSet(…, 1, …)`.
8. **Encoding.** A title with invalid UTF-8 bytes, and a 256-byte package
   name, to see how `GetCallingAppInfo` fills a full field.
9. **Version report on an old host.** On the oldest Play Services build at
   hand, call `GetWasmVersion` and record the value, to map levels to host
   releases.
10. **Short reads.** Register a blob larger than 1 MiB and log the counts
    `ReadCredentialsBuffer` returns for one large read.

[H]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/credentialmanager.h
[HH-first]: https://github.com/digitalcredentialsdev/CMWallet/blob/28d55e3987a63356cfe615821cfdba3bbf3c1925/matcher/credentialmanager.h
[HH-pay]: https://github.com/digitalcredentialsdev/CMWallet/commit/808b9246e9f34fc715bf8785f6f2bf758f3669c7
[HH-link]: https://github.com/digitalcredentialsdev/CMWallet/commit/a2094a7251ebf0ae84d3e6ba5d243e71bf39da70
[HH-inline]: https://github.com/digitalcredentialsdev/CMWallet/commit/e2c681bbda1a65c09d6b15857a8ec870ee087e83
[HH-v2]: https://github.com/digitalcredentialsdev/CMWallet/commit/ef2efeea7e4a7a506cd4846f9822afe78bf566b1
[HH-v3]: https://github.com/digitalcredentialsdev/CMWallet/commit/d17ac46151d37cbbbb072c5b5b975e2153db1c28
[HH-v4]: https://github.com/digitalcredentialsdev/CMWallet/commit/187c892395d48a9ddcbb8772f4f67d4eb81646f8
[HH-v5]: https://github.com/digitalcredentialsdev/CMWallet/commit/72b265b7599fe1e5ae6f764e1b0599f7c0dc6f8e
[HH-v6]: https://github.com/digitalcredentialsdev/CMWallet/commit/98e6c9c9848c77d3834bcd56dfa1b4bb146a65bb
[HH-v7]: https://github.com/digitalcredentialsdev/CMWallet/commit/4230483c69707bfe0c1617653703d7e4274e0799
[GC]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c
[GC-in]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L17-L33
[GC-len]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L35-L49
[GC-alt]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L51-L56
[GC-pay]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L91-L107
[GC-v2]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L132-L136
[GC-v1]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L111-L166
[GC-v5]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L167-L169
[GC-txn]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L306-L320
[GC-inline]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L380-L394
[GC-ver]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/openid4vp1_0.c#L424-L426
[GP]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/pnv/openid4vp1_0.c
[GP-partial]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/pnv/openid4vp1_0.c#L117-L129
[GP-v7]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/pnv/openid4vp1_0.c#L244-L251
[GP-link]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/pnv/openid4vp1_0.c#L253-L266
[GP-fields]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/pnv/openid4vp1_0.c#L267-L273
[GP-ver]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/pnv/openid4vp1_0.c#L332-L334
[GR]: https://github.com/digitalcredentialsdev/CMWallet/tree/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher-rs/src
[GR-bindings]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher-rs/src/bindings.rs#L9
[GR-credman]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher-rs/src/credman.rs#L108-L411
[GR-reporter]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher-rs/src/reporter.rs
[GR-start]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher-rs/src/bin/presentation.rs#L13-L18
[GA]: https://github.com/digitalcredentialsdev/CMWallet/tree/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/app/src/main/assets
[GT]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/test_runner.cc#L131-L223
[GT-plan]: https://github.com/digitalcredentialsdev/CMWallet/blob/abcf38a39cce77b656c7ffed1cffbbb9d58f75ac/matcher/test_plan.md#L189-L205
[AX-entry]: https://github.com/androidx/androidx/blob/2b7ce63091feaf4d7df5ab264581f074720946d0/credentials/registry/registry-provider/src/main/java/androidx/credentials/registry/provider/digitalcredentials/VerificationEntryDisplayProperties.kt#L22-L51
[AX-field]: https://github.com/androidx/androidx/blob/2b7ce63091feaf4d7df5ab264581f074720946d0/credentials/registry/registry-provider/src/main/java/androidx/credentials/registry/provider/digitalcredentials/VerificationFieldDisplayProperties.kt#L22-L39
[AX-inline]: https://github.com/androidx/androidx/blob/2b7ce63091feaf4d7df5ab264581f074720946d0/credentials/registry/registry-provider/src/main/java/androidx/credentials/registry/provider/digitalcredentials/InlineIssuanceEntry.kt#L47-L62
[AX-deleg]: https://github.com/androidx/androidx/blob/2b7ce63091feaf4d7df5ab264581f074720946d0/credentials/registry/registry-provider/src/main/java/androidx/credentials/registry/provider/DelegationType.kt#L40-L64
[AX-req]: https://github.com/androidx/androidx/blob/2b7ce63091feaf4d7df5ab264581f074720946d0/credentials/registry/registry-provider/src/main/java/androidx/credentials/registry/provider/RegisterCredentialsRequest.kt#L27-L31
[AX-select]: https://github.com/androidx/androidx/blob/2b7ce63091feaf4d7df5ab264581f074720946d0/credentials/registry/registry-provider/src/main/java/androidx/credentials/registry/provider/ProviderGetCredentialRequest.kt#L29-L95
[MP]: https://github.com/openwallet-foundation/multipaz/blob/5c15239f5875e4e9f42dc1fac7a62f0e4db533fe/multipaz-dcapi-credman/src/androidMain/matcher/CredentialDatabase.cpp#L380-L455
[SD-doc]: https://github.com/sirosfoundation/siros-dc-matcher/blob/ac573c2843afeb3d4d9d19924aa81572cabbd304/docs/abi.md#L31-L50
[SD-icon]: https://github.com/sirosfoundation/siros-dc-matcher/commit/3d61ac791f1f004914e0bbf732704cfc445755ce
[SD-badge]: https://github.com/sirosfoundation/siros-dc-matcher/commit/6cd02c9913da9ddca9a1d5fd0a73b0dc2730afbb
[EP]: https://github.com/digitallabor-berlin/elpaso/blob/4f89c660b1d19fa801e863ac16e6352f560af500/matcher/patches/0003-non-payment-sca-entry-fallback.patch
[SP]: https://github.com/Sphereon-Opensource/mobile-wallet/blob/19bcf4972db4a1a15fb5ac2a260bb719bdd21ab6/matcher-build/src/lib.rs#L19-L37
[SR]: https://github.com/sirosfoundation/siros-dc-matcher/releases/tag/v0.8.0
