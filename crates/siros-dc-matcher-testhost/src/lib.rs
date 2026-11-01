//! A host implementation of the Credential Manager matcher ABI.
//!
//! In production the only thing that implements this ABI is Play Services,
//! which means the only way to exercise a matcher is to install it on a phone
//! and drive a real verifier. That is a poor place to discover that a DCQL
//! `claim_sets` edge case is wrong.
//!
//! This crate implements the same ABI over wasmtime, so the real `.wasm`
//! binary runs against fixtures in ordinary `cargo test`. It also lets the
//! same fixtures be replayed against another implementation for differential
//! testing — see `CONTRIBUTING.md` on why that oracle is never vendored into
//! this repository.

#![deny(missing_docs)]
#![deny(unsafe_code)]
// std's HashMap and HashSet are safe outside matcher.wasm.
#![allow(clippy::disallowed_types)]
// Nothing panics outside the tests. scripts/check_panic_sites.py refuses an
// allow of these lints there and finds the panics they cannot see.
#![cfg_attr(
    not(test),
    deny(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::disallowed_methods
    )
)]

use std::num::NonZeroUsize;

use anyhow::{Context, Result};
use wasmtime::{Caller, Engine, Extern, Linker, Memory, Module, Store};
use wasmtime_wasi::pipe::MemoryOutputPipe;
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::WasiCtxBuilder;

/// The most a matcher may write to stderr in one run.
const STDERR_CAPACITY: usize = 1 << 20;

/// What the host offers a matcher on one invocation.
#[derive(Debug, Clone, Default)]
pub struct Invocation {
    /// The DC API request JSON, shaped `{"requests":[{"protocol":…,"data":…}]}`.
    pub request: Vec<u8>,
    /// The credential blob the wallet registered. Format is the wallet's own.
    pub credentials: Vec<u8>,
    /// Package name of the calling app, as the platform verified it.
    pub calling_package: String,
    /// Verified web origin, empty when the caller is a native app.
    pub origin: String,
    /// Host ABI version reported through `GetWasmVersion`.
    pub wasm_version: u32,
    /// How the host answers each `ReadCredentialsBuffer` call.
    pub credential_reads: CredentialReads,
}

/// How the host answers `ReadCredentialsBuffer`: copy from the blob at the
/// offset asked, at most the length asked, and report the count copied.
/// The last two variants break that contract.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CredentialReads {
    /// Each call copies all the bytes asked for that the blob holds.
    #[default]
    Whole,
    /// Each call copies at most this many bytes.
    Chunks(NonZeroUsize),
    /// Each call copies what [`CredentialReads::Whole`] copies and reports
    /// one byte more.
    OverReport,
    /// Each call copies nothing and reports 0, before the end of the blob
    /// too.
    Stall,
}

impl CredentialReads {
    /// The bytes one call copies from `blob` at `offset`, at most `len` of
    /// them, and the count it reports. Past the end it copies nothing.
    fn answer(self, blob: &[u8], offset: usize, len: usize) -> (&[u8], usize) {
        let remaining = blob.get(offset..).unwrap_or_default();
        let most = match self {
            Self::Whole | Self::OverReport => len,
            Self::Chunks(chunk) => len.min(chunk.get()),
            Self::Stall => 0,
        };
        let copied = remaining.get(..most).unwrap_or(remaining);
        let reported = copied.len() + usize::from(self == Self::OverReport);
        (copied, reported)
    }
}

/// One credential the matcher offered to the picker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedEntry {
    /// Set this entry belongs to.
    pub set_id: String,
    /// Position within the set.
    pub index: i32,
    /// Wallet-side credential identifier.
    pub credential_id: String,
    /// Primary line shown to the user.
    pub title: String,
    /// Secondary line, typically the issuer.
    pub subtitle: String,
    /// Opaque payload handed back to the wallet on selection.
    pub metadata: String,
    /// Icon bytes the matcher passed, if any.
    pub icon: Vec<u8>,
    /// The disclaimer pointer, distinguishing absent from empty.
    ///
    /// `None` for a null pointer and `Some("")` for a pointer to an empty
    /// string. The distinction is the whole point: the real host renders the
    /// presence of this field, so an empty string draws a label with nothing
    /// in it — the v0.6.1 warning-badge bug. A capture that collapsed the two
    /// could not tell that bug from correct behaviour.
    pub disclaimer: Option<String>,
    /// The warning pointer, with the same absent-versus-empty distinction.
    pub warning: Option<String>,
    /// Display fields attached to this entry, in emission order.
    pub fields: Vec<(String, String)>,
    /// The delegation type sent at level 7.
    pub delegation: Option<i32>,
    /// The second disclaimer, link text and link target sent at level 6.
    pub link: Option<(String, String, String)>,
    /// The display text sent at level 5.
    pub metadata_display_text: Option<String>,
}

/// Everything a matcher emitted during one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    /// Sets declared, as `(set_id, declared_length)`.
    pub sets: Vec<(String, i32)>,
    /// Entries emitted, in order.
    pub entries: Vec<CapturedEntry>,
    /// What the matcher wrote to stderr.
    pub stderr: Vec<u8>,
}

impl Captured {
    /// The entry at `set_id`/`index`, if the matcher emitted one.
    pub fn entry(&self, set_id: &str, index: i32) -> Option<&CapturedEntry> {
        self.entries
            .iter()
            .find(|e| e.set_id == set_id && e.index == index)
    }

    /// Whether the matcher offered nothing.
    ///
    /// Worth naming, because in the picker this is indistinguishable from a
    /// trap: both show the user no wallet at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Host state threaded through the wasmtime store.
struct State {
    wasi: WasiP1Ctx,
    input: Invocation,
    out: Captured,
}

/// Run a matcher module against one invocation and capture what it emitted.
///
/// # Errors
///
/// Returns an error if the module fails to compile, fails to instantiate
/// (typically a host import it needs and we do not provide), or traps. The
/// error of a trap carries what the matcher wrote to stderr, where a
/// panicking matcher writes its panic message.
pub fn run(wasm: &[u8], input: Invocation) -> Result<Captured> {
    let (engine, module) = compiled(wasm)?;

    let stderr = MemoryOutputPipe::new(STDERR_CAPACITY);
    let mut store = Store::new(
        &engine,
        State {
            wasi: WasiCtxBuilder::new()
                .inherit_stdin()
                .inherit_stdout()
                .stderr(stderr.clone())
                .build_p1(),
            input,
            out: Captured::default(),
        },
    );

    let mut linker: Linker<State> = Linker::new(&engine);
    preview1::add_to_linker_sync(&mut linker, |s: &mut State| &mut s.wasi)
        .context("linking WASI preview 1")?;
    add_credman(&mut linker)?;
    // The real host links a module whose imports it lacks and traps when one
    // is called (ABI.md §3). The calls this host does not record behave the
    // same way.
    linker
        .define_unknown_imports_as_traps(&module)
        .context("defining the unrecorded imports")?;

    let instance = linker
        .instantiate(&mut store, &module)
        .context("instantiating matcher")?;

    let ran = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("matcher has no _start export")?
        .call(&mut store, ());
    let mut out = store.into_data().out;
    out.stderr = stderr.contents().to_vec();
    ran.with_context(|| {
        format!(
            "matcher trapped — in a real picker this shows the user nothing at all; \
             its stderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    })?;
    Ok(out)
}

/// Compile a module once per process, reusing it across runs.
///
/// Compiling is by far the slowest part of a run — the matcher is a few
/// hundred kilobytes and every test needs it — so recompiling per test turned
/// a fast suite into a slow one. Keyed by the bytes, because the guard tests
/// run hand-written modules of their own.
fn compiled(wasm: &[u8]) -> Result<(Engine, Module)> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static ENGINE: OnceLock<Engine> = OnceLock::new();
    #[allow(clippy::type_complexity)]
    static MODULES: OnceLock<Mutex<HashMap<Vec<u8>, Module>>> = OnceLock::new();

    let engine = ENGINE.get_or_init(Engine::default).clone();

    // Keyed by the bytes themselves, not a hash of them. A collision would
    // silently run the wrong module, and "the wrong module ran" is close to
    // undiagnosable from a failing assertion. Only a handful of modules are
    // ever cached, so the copies cost nothing worth saving.
    let cache = MODULES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    let module = match cache.get(wasm) {
        Some(module) => module.clone(),
        None => {
            let module = Module::new(&engine, wasm).context("compiling matcher module")?;
            cache.insert(wasm.to_vec(), module.clone());
            module
        }
    };
    Ok((engine, module))
}

/// Register the `credman` to `credman_v7` imports a matcher links against.
fn add_credman(linker: &mut Linker<State>) -> Result<()> {
    linker.func_wrap(
        "credman",
        "GetWasmVersion",
        |mut c: Caller<'_, State>, ptr: i32| {
            let v = c.data().input.wasm_version;
            write_u32(&mut c, ptr, v)
        },
    )?;

    linker.func_wrap(
        "credman",
        "GetRequestSize",
        |mut c: Caller<'_, State>, ptr: i32| {
            let n = c.data().input.request.len() as u32;
            write_u32(&mut c, ptr, n)
        },
    )?;

    linker.func_wrap(
        "credman",
        "GetRequestBuffer",
        |mut c: Caller<'_, State>, ptr: i32| {
            let bytes = c.data().input.request.clone();
            write_bytes(&mut c, ptr, &bytes)
        },
    )?;

    linker.func_wrap(
        "credman",
        "GetCredentialsSize",
        |mut c: Caller<'_, State>, ptr: i32| {
            let n = c.data().input.credentials.len() as u32;
            write_u32(&mut c, ptr, n)
        },
    )?;

    // The offset and the length are `size_t`, unsigned on wasm32. Returns the
    // count the host reports, as `Invocation::credential_reads` answers.
    linker.func_wrap(
        "credman",
        "ReadCredentialsBuffer",
        |mut c: Caller<'_, State>, ptr: i32, offset: u32, len: u32| -> Result<i32> {
            let input = &c.data().input;
            let (copied, reported) =
                input
                    .credential_reads
                    .answer(&input.credentials, offset as usize, len as usize);
            let copied = copied.to_vec();
            write_bytes(&mut c, ptr, &copied)?;
            i32::try_from(reported).context("a read count beyond i32")
        },
    )?;

    // Fixed-size NUL-padded buffers: 256 bytes of package name followed by
    // 512 of origin. The sizes are part of the ABI, not a convention.
    linker.func_wrap(
        "credman",
        "GetCallingAppInfo",
        |mut c: Caller<'_, State>, ptr: i32| {
            let (pkg, origin) = {
                let i = &c.data().input;
                (i.calling_package.clone(), i.origin.clone())
            };
            let mut buf = Vec::with_capacity(256 + 512);
            buf.extend_from_slice(&padded::<256>(&pkg));
            buf.extend_from_slice(&padded::<512>(&origin));
            write_bytes(&mut c, ptr, &buf)
        },
    )?;

    linker.func_wrap(
        "credman_v2",
        "AddEntrySet",
        |mut c: Caller<'_, State>, set_id: i32, len: i32| -> Result<()> {
            let set_id = read_cstr(&mut c, set_id)?;
            c.data_mut().out.sets.push((set_id, len));
            Ok(())
        },
    )?;

    #[allow(clippy::too_many_arguments)]
    linker.func_wrap(
        "credman_v2",
        "AddEntryToSet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         icon: i32,
         icon_len: i32,
         title: i32,
         subtitle: i32,
         disclaimer: i32,
         warning: i32,
         metadata: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            // Read the icon by pointer and length, not as a C string: it is
            // arbitrary bytes and a PNG contains NULs, so treating it as text
            // would silently truncate at the first one.
            let icon = read_bytes(&mut c, icon, icon_len)?;
            let entry = CapturedEntry {
                set_id: read_cstr(&mut c, set_id)?,
                index,
                credential_id: read_cstr(&mut c, cred_id)?,
                title: read_cstr(&mut c, title)?,
                subtitle: read_cstr(&mut c, subtitle)?,
                metadata: read_cstr(&mut c, metadata)?,
                icon,
                disclaimer: read_cstr_opt(&mut c, disclaimer)?,
                warning: read_cstr_opt(&mut c, warning)?,
                fields: Vec::new(),
                delegation: None,
                link: None,
                metadata_display_text: None,
            };
            c.data_mut().out.entries.push(entry);
            Ok(())
        },
    )?;

    linker.func_wrap(
        "credman_v2",
        "AddFieldToEntrySet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         name: i32,
         value: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            let (cred_id, set_id, name, value) = (
                read_cstr(&mut c, cred_id)?,
                read_cstr(&mut c, set_id)?,
                read_cstr(&mut c, name)?,
                read_cstr(&mut c, value)?,
            );
            let entry = entry_at(&mut c.data_mut().out, &set_id, index, &cred_id)?;
            entry.fields.push((name, value));
            Ok(())
        },
    )?;

    linker.func_wrap(
        "credman_v5",
        "AddMetadataDisplayTextToEntrySet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         text: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            reached(&c, 5, "AddMetadataDisplayTextToEntrySet")?;
            let (cred_id, text, set_id) = (
                read_cstr(&mut c, cred_id)?,
                read_cstr(&mut c, text)?,
                read_cstr(&mut c, set_id)?,
            );
            entry_at(&mut c.data_mut().out, &set_id, index, &cred_id)?.metadata_display_text =
                Some(text);
            Ok(())
        },
    )?;

    linker.func_wrap(
        "credman_v6",
        "SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         disclaimer: i32,
         url_text: i32,
         url: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            reached(
                &c,
                6,
                "SetAdditionalDisclaimerAndUrlForVerificationEntryInCredentialSet",
            )?;
            let (cred_id, link, set_id) = (
                read_cstr(&mut c, cred_id)?,
                (
                    read_cstr(&mut c, disclaimer)?,
                    read_cstr(&mut c, url_text)?,
                    read_cstr(&mut c, url)?,
                ),
                read_cstr(&mut c, set_id)?,
            );
            entry_at(&mut c.data_mut().out, &set_id, index, &cred_id)?.link = Some(link);
            Ok(())
        },
    )?;

    linker.func_wrap(
        "credman_v7",
        "SetDelegationTypeForEntryInSet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         delegation: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            reached(&c, 7, "SetDelegationTypeForEntryInSet")?;
            let (cred_id, set_id) = (read_cstr(&mut c, cred_id)?, read_cstr(&mut c, set_id)?);
            entry_at(&mut c.data_mut().out, &set_id, index, &cred_id)?.delegation =
                Some(delegation);
            Ok(())
        },
    )?;

    Ok(())
}

/// A call above the reported level traps on a real host.
fn reached(c: &Caller<'_, State>, level: u32, function: &str) -> Result<()> {
    let reported = c.data().input.wasm_version;
    if reported < level {
        return Err(anyhow::anyhow!(
            "{function} is level {level}, called on a level-{reported} host"
        ));
    }
    Ok(())
}

/// The entry a field or a level-5 to level-7 call names.
///
/// The platform keys these calls by set, position and credential id: the
/// alternatives at one position differ in their credential id alone. A call
/// for an entry that was never added is a matcher bug, and silently dropping
/// it would hide exactly that bug; a call with a credential id no alternative
/// carries never attaches in a real picker.
fn entry_at<'o>(
    out: &'o mut Captured,
    set_id: &str,
    index: i32,
    cred_id: &str,
) -> Result<&'o mut CapturedEntry> {
    let at_position = |e: &CapturedEntry| e.set_id == set_id && e.index == index;
    let added: Vec<String> = out
        .entries
        .iter()
        .filter(|e| at_position(e))
        .map(|e| e.credential_id.clone())
        .collect();
    out.entries
        .iter_mut()
        .find(|e| at_position(e) && e.credential_id == cred_id)
        .ok_or_else(|| {
            if added.is_empty() {
                anyhow::anyhow!("call for unknown entry {set_id}[{index}]")
            } else {
                anyhow::anyhow!(
                    "call for entry {set_id}[{index}] carries credential id {cred_id:?}, \
                     but the entries there were added as {added:?}"
                )
            }
        })
}

/// The guest's linear memory.
fn memory(c: &mut Caller<'_, State>) -> Result<Memory> {
    match c.get_export("memory") {
        Some(Extern::Memory(m)) => Ok(m),
        _ => Err(anyhow::anyhow!("matcher does not export `memory`")),
    }
}

fn write_u32(c: &mut Caller<'_, State>, ptr: i32, value: u32) -> Result<()> {
    write_bytes(c, ptr, &value.to_le_bytes())
}

fn write_bytes(c: &mut Caller<'_, State>, ptr: i32, bytes: &[u8]) -> Result<()> {
    let mem = memory(c)?;
    mem.write(c, ptr as usize, bytes)
        .context("matcher passed a pointer outside its own memory")
}

/// Read `len` bytes from guest memory.
///
/// A null pointer or zero length means "no value", which is how the ABI says
/// an entry has no icon.
fn read_bytes(c: &mut Caller<'_, State>, ptr: i32, len: i32) -> Result<Vec<u8>> {
    if ptr == 0 || len <= 0 {
        return Ok(Vec::new());
    }
    let mem = memory(c)?;
    let data = mem.data(&c);
    let start = ptr as usize;
    let end = start
        .checked_add(len as usize)
        .context("icon length overflows the address space")?;
    data.get(start..end)
        .map(<[u8]>::to_vec)
        .context("matcher passed an icon outside its own memory")
}

/// Read a NUL-terminated string the guest passed as `char*`.
/// A C string the matcher may legitimately have omitted.
///
/// `None` for a null pointer, `Some` for anything else — including a pointer
/// to `""`, which is a real value the host treats differently from absence.
fn read_cstr_opt(c: &mut Caller<'_, State>, ptr: i32) -> Result<Option<String>> {
    if ptr == 0 {
        return Ok(None);
    }
    read_cstr(c, ptr).map(Some)
}

fn read_cstr(c: &mut Caller<'_, State>, ptr: i32) -> Result<String> {
    if ptr == 0 {
        return Ok(String::new());
    }
    let mem = memory(c)?;
    let data = mem.data(&c);
    let start = ptr as usize;
    let tail = data
        .get(start..)
        .context("matcher passed a pointer outside its own memory")?;
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(tail.get(..end).unwrap_or_default()).into_owned())
}

/// `value` NUL-padded into a fixed-width ABI field, cut to leave the last
/// byte NUL.
fn padded<const WIDTH: usize>(value: &str) -> [u8; WIDTH] {
    let mut field = [0u8; WIDTH];
    let room = WIDTH.saturating_sub(1);
    for (slot, byte) in field.iter_mut().zip(value.bytes().take(room)) {
        *slot = byte;
    }
    field
}
