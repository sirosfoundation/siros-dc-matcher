#!/usr/bin/env node
// Run the real matcher.wasm outside Rust, against a request of your choosing.
//
//   node scripts/run_matcher.mjs                       # built-in signed request
//   node scripts/run_matcher.mjs path/to/request.json  # one you captured
//
// Why this exists: the Rust integration tests in
// crates/siros-dc-matcher-testhost cover the same ground and are what CI runs.
// This is for the other situation — a request captured off a real verifier that
// produces no picker entry, where the question is "what does the binary
// actually do with these bytes", and the answer needs to arrive in seconds
// without writing a test first. It has been rebuilt from scratch three times
// under exactly that pressure; hence committing it.
//
// It is a stub host, not the Android one. It cannot reproduce the two host
// behaviours that have cost the most time — a null icon dropping the entry, and
// a duplicate set id discarding the whole output — so it reports both instead.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const WASM = join(root, 'target/wasm32-wasip1/wasm-release/matcher.wasm');
const BLOB = join(root, 'crates/siros-dc-matcher-core/tests/golden/credential_database_v1.cbor');

const b64url = (s) => Buffer.from(s, 'utf8').toString('base64url');

/** A signed request in the shape OpenID4VP 1.0 Appendix A describes. */
function defaultRequest() {
  const object = JSON.stringify({
    client_id: 'x509_san_dns:verifier.example',
    response_mode: 'dc_api.jwt',
    nonce: 'n-0S6_WzA2Mj',
    expected_origins: ['https://verifier.example'],
    dcql_query: {
      credentials: [{
        id: 'q1',
        format: 'mso_mdoc',
        meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
        claims: [{ path: ['org.iso.18013.5.1', 'age_over_18'] }],
      }],
    },
    client_metadata: { jwks: { keys: [] } },
  });
  const jws = `${b64url('{"alg":"ES256"}')}.${b64url(object)}.${b64url('signature')}`;
  return JSON.stringify({ requests: [{ protocol: 'openid4vp-v1-signed', data: { request: jws } }] });
}

const [, , requestPath] = process.argv;
const requestText = requestPath ? await readFile(requestPath, 'utf8') : defaultRequest();
const request = Buffer.from(requestText, 'utf8');
const credentials = await readFile(BLOB);

let memory;
const str = (ptr) => {
  if (ptr === 0) return null;
  const bytes = new Uint8Array(memory.buffer, ptr);
  let end = 0;
  while (bytes[end] !== 0) end++;
  return Buffer.from(bytes.subarray(0, end)).toString('utf8');
};
const u32 = (ptr, value) => new DataView(memory.buffer).setUint32(ptr, value, true);

const sets = [];
const entries = [];
const fields = [];
let nullIcons = 0;

const credman = {
  GetCallingAppInfo(ptr) {
    // package_name[256] then origin[512], both NUL-terminated in place.
    const view = new Uint8Array(memory.buffer, ptr, 256 + 512);
    view.fill(0);
    Buffer.from('com.android.chrome\0', 'utf8').copy(view, 0);
    Buffer.from('https://verifier.example\0', 'utf8').copy(view, 256);
  },
  GetRequestSize: (ptr) => u32(ptr, request.length),
  GetRequestBuffer: (ptr) => new Uint8Array(memory.buffer, ptr, request.length).set(request),
  GetCredentialsSize: (ptr) => u32(ptr, credentials.length),
  ReadCredentialsBuffer(ptr, offset, len) {
    const slice = credentials.subarray(offset, offset + len);
    new Uint8Array(memory.buffer, ptr, slice.length).set(slice);
    return slice.length;
  },
  GetWasmVersion: (ptr) => u32(ptr, 2),
};

const credman_v2 = {
  AddEntrySet: (setId, length) => sets.push({ id: str(setId), length }),
  AddEntryToSet(credId, icon, iconLen, title, subtitle, disclaimer, warning, metadata, setId, index) {
    if (icon === 0 || iconLen === 0) nullIcons++;
    entries.push({
      setId: str(setId), index, credentialId: str(credId),
      title: str(title), subtitle: str(subtitle),
      iconBytes: icon === 0 ? 0 : iconLen,
      metadata: str(metadata),
      disclaimer: str(disclaimer), warning: str(warning),
    });
  },
  AddFieldToEntrySet: (credId, name, value, setId, index) =>
    fields.push({ setId: str(setId), index, credentialId: str(credId), name: str(name), value: str(value) }),
};

// The host's WASI is a subset. These are the only two the shipped binary
// imports, and both come from rustc's CRT rather than from our code.
const wasi_snapshot_preview1 = {
  environ_sizes_get: (countPtr, sizePtr) => (u32(countPtr, 0), u32(sizePtr, 0), 0),
  environ_get: () => 0,
  proc_exit: () => {},
  fd_write: () => 0,
  fd_close: () => 0,
  fd_seek: () => 0,
};

const { instance } = await WebAssembly.instantiate(await readFile(WASM), {
  credman, credman_v2, wasi_snapshot_preview1,
});
memory = instance.exports.memory;
instance.exports._start();

console.log(`request: ${request.length} bytes${requestPath ? ` from ${requestPath}` : ' (built-in signed example)'}`);
console.log(`blob:    ${credentials.length} bytes\n`);

if (sets.length === 0) {
  console.log('No entries. That is what an unsatisfiable request looks like too — turn');
  console.log('profile.debug on in the registered blob to get the reason as an entry.');
} else {
  for (const set of sets) {
    console.log(`set ${set.id} (declared length ${set.length})`);
    for (const e of entries.filter((e) => e.setId === set.id)) {
      console.log(`  [${e.index}] ${e.credentialId} — ${e.title} / ${e.subtitle}`);
      console.log(`       icon: ${e.iconBytes} bytes`);
      console.log(`       metadata: ${e.metadata}`);
      for (const f of fields.filter((f) => f.setId === set.id && f.index === e.index)) {
        console.log(`       field: ${f.name} = ${f.value}`);
      }
    }
  }
}

// The two host behaviours this stub cannot reproduce, checked rather than
// assumed. Both are silent on a device: the picker simply shows less, or
// nothing, with no error anywhere the wallet can see.
const problems = [];
if (nullIcons > 0) {
  problems.push(`${nullIcons} entry/entries have a null icon — the Android host drops each one and logs "Null icon for icon" in its own process`);
}
// A 4x4 PNG was dropped on a device just as a null icon was, so "present" is
// not the same as "big enough". The exact threshold is unknown; 64x64 is what
// is known to work, and anything far below it is worth a second look.
const TINY_ICON = 256;
const tiny = entries.filter((e) => e.iconBytes > 0 && e.iconBytes < TINY_ICON);
if (tiny.length > 0) {
  console.log(`\nWarning: ${tiny.length} entry/entries carry under ${TINY_ICON} bytes of icon`);
  console.log('  (a 4x4 PNG was dropped on a device; 64x64 is known to work). Fine for a');
  console.log('  fixture, not for anything a wallet registers for real.');
}

const ids = sets.map((s) => s.id);
const duplicates = [...new Set(ids.filter((id, i) => ids.indexOf(id) !== i))];
if (duplicates.length > 0) {
  problems.push(`duplicate set id(s) ${duplicates.join(', ')} — the Android host discards the entire output`);
}
if (problems.length > 0) {
  console.log('\nWould fail on a device:');
  for (const p of problems) console.log(`  - ${p}`);
  process.exitCode = 1;
}
