"""Writes docs/ecosystem.svg: the layers of the wallet core, its artifacts and its host.

Run from the repository root: python3 scripts/gen_ecosystem_svg.py docs/ecosystem.svg
"""
import sys
from html import escape

W = 1440
LABEL_X, CONTENT_X, CONTENT_W = 32, 210, 956
BAND_RIGHT = 1180
HOST_X, HOST_W = 1228, 196
GAP = 12
CHIP_H = 50

# (key, label, caption, rows of (name, description))
BANDS = [
    ("art", "Artifacts", "what consumers install", [[
        ("matcher.wasm", "Credential Manager picker"),
        ("Android AAR", "UniFFI bindings + matcher.wasm"),
        ("XCFramework", "UniFFI bindings for iOS"),
        ("browser presenter", "zkp_req proofs in the browser"),
    ]]),
    ("l4", "L4", "facades · picker · provers", [
        [
            ("siros-picker", "the picker binary"),
            ("siros-registration", "the picker's registration"),
            ("android-credman", "host ABI as types"),
            ("android-credman-sys", "Credential Manager imports"),
        ],
        [
            ("siros-dc-matcher-ffi", "UniFFI surface"),
            ("siros-dc-matcher-core", "v1 blob and profile, for the FFI"),
            ("siros-picker-testhost", "the picker off-device"),
            ("siros-zkp-req-wasm", "browser presenter"),
        ],
        [
            ("siros-zkp-backend-longfellow", "Longfellow prover"),
            ("siros-zkp-backend-vega", "Vega prover"),
            ("siros-zkp-proving-e2e", "real proofs end to end"),
        ],
    ]),
    ("l3", "L3", "presentation", [[
        ("siros-presentation",
         "plan · offers · consent view · selection · signing inputs · vp_token · record"),
    ]]),
    ("l2", "L2", "wallet model", [[
        ("siros-wallet-state", "decrypted private data"),
        ("siros-credential", "typed credentials, issuer chain"),
        ("siros-display", "cards and rows, one language"),
        ("siros-transaction-data", "PaSO and TS12 transactions"),
    ]]),
    ("l1", "L1", "protocols · formats · trust", [
        [
            ("siros-dcql", "DCQL · on crates.io"),
            ("siros-oid4vp", "OpenID4VP intake, response"),
            ("siros-sdjwt", "SD-JWT VC"),
            ("siros-mdoc", "ISO mdoc"),
        ],
        [
            ("siros-zkp-req", "zkp_req protocol"),
            ("siros-zkp-req-nym-auth", "nym_auth catalogue"),
            ("siros-trust", "trust store, issuer chains"),
        ],
    ]),
    ("l0", "L0", "encodings", [[
        ("siros-codec", "strict CBOR and JSON · base64url · shared types"),
    ]]),
]

HOST_ITEMS = [
    ("Storage", "wallet state, held metadata"),
    ("Keys", "signing through wscd"),
    ("Network", "Fetch effects"),
    ("Trust", "store provisioning, verdicts"),
    ("Platform", "clock, language, UI"),
]

STYLE = """
  .bg { fill: #ffffff; }
  .title { font: 700 26px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #0f172a; }
  .subtitle { font: 400 14px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #475569; }
  .layer { font: 700 22px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #0f172a; }
  .caption { font: 400 13px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #475569; }
  .name { font: 600 12px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; fill: #0f172a; }
  .desc { font: 400 11.5px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #475569; }
  .note { font: 400 12px system-ui, -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; fill: #64748b; }
  .chip { fill: #ffffff; stroke-width: 1.5; }
  .arrow { stroke: #64748b; stroke-width: 1.5; fill: none; }
  .head { fill: #64748b; }
  .band-art { fill: #f1f5f9; } .chip-art { stroke: #94a3b8; }
  .band-l4 { fill: #ede9fe; } .chip-l4 { stroke: #8b5cf6; }
  .band-l3 { fill: #dbeafe; } .chip-l3 { stroke: #3b82f6; }
  .band-l2 { fill: #dcfce7; } .chip-l2 { stroke: #22c55e; }
  .band-l1 { fill: #fef3c7; } .chip-l1 { stroke: #f59e0b; }
  .band-l0 { fill: #ffe4e6; } .chip-l0 { stroke: #f43f5e; }
  .host { fill: #f8fafc; stroke: #94a3b8; stroke-width: 1.5; stroke-dasharray: 6 4; }
  @media (prefers-color-scheme: dark) {
    .bg { fill: #0d1117; }
    .title, .layer, .name { fill: #e6edf3; }
    .subtitle, .caption, .desc { fill: #9da7b3; }
    .note { fill: #8b949e; }
    .chip { fill: #161b22; }
    .arrow { stroke: #8b949e; } .head { fill: #8b949e; }
    .band-art { fill: #1c2128; }
    .band-l4 { fill: #231b3d; }
    .band-l3 { fill: #132339; }
    .band-l2 { fill: #12291b; }
    .band-l1 { fill: #2f2410; }
    .band-l0 { fill: #33151c; }
    .host { fill: #161b22; stroke: #6e7681; }
  }
"""


def chip(out, key, x, y, w, name, desc):
    out.append(f'<rect class="chip chip-{key}" x="{x}" y="{y}" width="{w}" height="{CHIP_H}" rx="9"/>')
    cx = x + w / 2
    out.append(f'<text class="name" x="{cx}" y="{y + 21}" text-anchor="middle">{escape(name)}</text>')
    out.append(f'<text class="desc" x="{cx}" y="{y + 38}" text-anchor="middle">{escape(desc)}</text>')


def band(out, key, label, caption, rows, top):
    pad = 14
    height = pad * 2 + len(rows) * CHIP_H + (len(rows) - 1) * 10
    out.append(f'<rect class="band-{key}" x="16" y="{top}" width="{BAND_RIGHT - 16}" height="{height}" rx="14"/>')
    mid = top + height / 2
    out.append(f'<text class="layer" x="{LABEL_X}" y="{mid - 2}">{escape(label)}</text>')
    out.append(f'<text class="caption" x="{LABEL_X}" y="{mid + 18}">{escape(caption)}</text>')
    for i, row in enumerate(rows):
        y = top + pad + i * (CHIP_H + 10)
        columns = 4 if len(row) > 1 else 1
        width = (CONTENT_W - (columns - 1) * GAP) / columns
        for j, (name, desc) in enumerate(row):
            chip(out, key, CONTENT_X + j * (width + GAP), y, width, name, desc)
    return top + height


def main(path):
    out = []
    y = 92
    tops = {}
    for key, label, caption, rows in BANDS:
        tops[key] = y
        bottom = band(out, key, label, caption, rows, y)
        tops[key + "_end"] = bottom
        y = bottom + 14
    height = y + 34

    # The host, beside the core layers.
    host_top, host_bottom = tops["l4"], tops["l0_end"]
    out.append(f'<rect class="host" x="{HOST_X}" y="{host_top}" width="{HOST_W}" height="{host_bottom - host_top}" rx="14"/>')
    out.append(f'<text class="layer" x="{HOST_X + 18}" y="{host_top + 34}">Host</text>')
    out.append(f'<text class="caption" x="{HOST_X + 18}" y="{host_top + 54}">each platform</text>')
    step = (host_bottom - host_top - 120) / (len(HOST_ITEMS) - 1)
    for i, (name, desc) in enumerate(HOST_ITEMS):
        iy = host_top + 92 + i * step
        out.append(f'<text class="name" x="{HOST_X + 18}" y="{iy}">{escape(name)}</text>')
        out.append(f'<text class="desc" x="{HOST_X + 18}" y="{iy + 17}">{escape(desc)}</text>')

    # Inputs and effects between the core and the host.
    ay = (host_top + host_bottom) / 2
    x1, x2 = BAND_RIGHT + 8, HOST_X - 8
    out.append(f'<path class="arrow" d="M {x1} {ay - 6} H {x2}"/>')
    out.append(f'<path class="head" d="M {x2 + 4} {ay - 6} l -8 -4 v 8 z"/>')
    out.append(f'<path class="arrow" d="M {x2} {ay + 6} H {x1}"/>')
    out.append(f'<path class="head" d="M {x1 - 4} {ay + 6} l 8 -4 v 8 z"/>')

    note = ("Dependencies point down the layers. The core is sans-IO: the host supplies its inputs "
            "and answers its Fetch, Sign and Trust effects.")
    out.append(f'<text class="note" x="32" y="{height - 16}">{escape(note)}</text>')

    head = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {height}" width="{W}" height="{height}" '
        'role="img" aria-labelledby="title desc">',
        '<title id="title">SIROS wallet core: layers, artifacts and host</title>',
        '<desc id="desc">The crates of the workspace in five layers, the artifacts built from them, '
        'and the host each platform provides.</desc>',
        f"<style>{STYLE}</style>",
        f'<rect class="bg" width="{W}" height="{height}" rx="18"/>',
        '<text class="title" x="32" y="48">SIROS wallet core</text>',
        '<text class="subtitle" x="32" y="72">The Rust workspace in layers, what it ships, and what each platform provides</text>',
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(head + out + ["</svg>", ""]))


if __name__ == "__main__":
    main(sys.argv[1])
