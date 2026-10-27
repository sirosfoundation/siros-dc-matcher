//! The `credman` to `credman_v7` imports the host gives a matcher, recorded into [`Captured`].

use anyhow::{Context, Result};
use wasmtime::{Caller, Extern, Linker, Memory};

use crate::{Captured, CapturedEntry, CapturedPayment, State};

/// Register the `credman` to `credman_v7` imports a matcher links against.
pub(crate) fn add_credman(linker: &mut Linker<State>) -> Result<()> {
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

    // Returns how many bytes were actually read, which is not necessarily the
    // number asked for — a matcher may request past the end of the blob.
    linker.func_wrap(
        "credman",
        "ReadCredentialsBuffer",
        |mut c: Caller<'_, State>, ptr: i32, offset: i32, len: i32| -> Result<i32> {
            let blob = c.data().input.credentials.clone();
            let start = (offset.max(0) as usize).min(blob.len());
            let end = start.saturating_add(len.max(0) as usize).min(blob.len());
            let slice = blob.get(start..end).unwrap_or_default().to_vec();
            write_bytes(&mut c, ptr, &slice)?;
            Ok(slice.len() as i32)
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
            let mut buf = vec![0u8; 256 + 512];
            write_padded(&mut buf, 0, 256, &pkg);
            write_padded(&mut buf, 256, 512, &origin);
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
                payment: None,
            };
            c.data_mut().out.entries.push(entry);
            Ok(())
        },
    )?;

    #[allow(clippy::too_many_arguments)]
    linker.func_wrap(
        "credman_v2",
        "AddPaymentEntryToSet",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         merchant: i32,
         method: i32,
         method_subtitle: i32,
         icon: i32,
         icon_len: i32,
         amount: i32,
         _bank_icon: i32,
         _bank_icon_len: i32,
         _provider_icon: i32,
         _provider_icon_len: i32,
         metadata: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            let payment = PaymentCall {
                cred_id,
                merchant,
                method,
                method_subtitle,
                icon: (icon, icon_len),
                amount,
                additional_info: 0,
                metadata,
                set_id,
                index,
            };
            add_payment(&mut c, &payment)
        },
    )?;

    #[allow(clippy::too_many_arguments)]
    linker.func_wrap(
        "credman_v2",
        "AddPaymentEntryToSetV2",
        |mut c: Caller<'_, State>,
         cred_id: i32,
         merchant: i32,
         method: i32,
         method_subtitle: i32,
         icon: i32,
         icon_len: i32,
         amount: i32,
         _bank_icon: i32,
         _bank_icon_len: i32,
         _provider_icon: i32,
         _provider_icon_len: i32,
         additional_info: i32,
         metadata: i32,
         set_id: i32,
         index: i32|
         -> Result<()> {
            reached(&c, 3, "AddPaymentEntryToSetV2")?;
            let payment = PaymentCall {
                cred_id,
                merchant,
                method,
                method_subtitle,
                icon: (icon, icon_len),
                amount,
                additional_info,
                metadata,
                set_id,
                index,
            };
            add_payment(&mut c, &payment)
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

/// The pointers of a call that adds a payment entry to a set.
struct PaymentCall {
    cred_id: i32,
    merchant: i32,
    method: i32,
    method_subtitle: i32,
    icon: (i32, i32),
    amount: i32,
    /// 0 for `AddPaymentEntryToSet`, which has none.
    additional_info: i32,
    metadata: i32,
    set_id: i32,
    index: i32,
}

/// Records the payment entry of `call`.
fn add_payment(c: &mut Caller<'_, State>, call: &PaymentCall) -> Result<()> {
    let entry = CapturedEntry {
        set_id: read_cstr(c, call.set_id)?,
        index: call.index,
        credential_id: read_cstr(c, call.cred_id)?,
        title: read_cstr(c, call.method)?,
        subtitle: read_cstr(c, call.method_subtitle)?,
        metadata: read_cstr(c, call.metadata)?,
        icon: read_bytes(c, call.icon.0, call.icon.1)?,
        disclaimer: None,
        warning: None,
        fields: Vec::new(),
        delegation: None,
        link: None,
        metadata_display_text: None,
        payment: Some(CapturedPayment {
            merchant: read_cstr(c, call.merchant)?,
            amount: read_cstr(c, call.amount)?,
            additional_info: read_cstr_opt(c, call.additional_info)?,
        }),
    };
    c.data_mut().out.entries.push(entry);
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
/// A call for an entry that was never added is a matcher bug, and silently
/// dropping it would hide exactly that bug. The credential id is checked as
/// well: the platform keys these calls by credential id as well as set
/// position, so a guest passing the wrong one produces calls that never
/// attach in a real picker.
fn entry_at<'o>(
    out: &'o mut Captured,
    set_id: &str,
    index: i32,
    cred_id: &str,
) -> Result<&'o mut CapturedEntry> {
    let entry = out
        .entries
        .iter_mut()
        .find(|e| e.set_id == set_id && e.index == index)
        .ok_or_else(|| anyhow::anyhow!("call for unknown entry {set_id}[{index}]"))?;
    if cred_id != entry.credential_id {
        return Err(anyhow::anyhow!(
            "call for entry {set_id}[{index}] carries credential id {cred_id:?}, \
             but the entry was added as {:?}",
            entry.credential_id
        ));
    }
    Ok(entry)
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

/// Write `value` NUL-padded into a fixed-width ABI field.
fn write_padded(buf: &mut [u8], offset: usize, width: usize, value: &str) {
    let src = value.as_bytes();
    let n = src.len().min(width.saturating_sub(1));
    if let (Some(dst), Some(src)) = (buf.get_mut(offset..offset + n), src.get(..n)) {
        dst.copy_from_slice(src);
    }
}
