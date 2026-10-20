#!/bin/sh
# Prints the sha256 manifest of the zkp_req conformance vectors and the vector
# set digest: the sha256 of that manifest (LC_ALL=C sorted, `sha256sum` format,
# paths relative to tests/vectors, README.md files excluded).
#
#   scripts/vectors_digest.sh            # manifest, then "set digest: <hex>"
#   scripts/vectors_digest.sh --digest   # only the hex digest
set -eu
cd "$(dirname "$0")/../crates/siros-dc-matcher-core/tests/vectors"
manifest=$(find zkp_req zkp_req_response zkp_req_unsat proof_time -name '*.json' | LC_ALL=C sort | xargs sha256sum)
digest=$(printf '%s\n' "$manifest" | sha256sum | cut -d' ' -f1)
if [ "${1:-}" = "--digest" ]; then echo "$digest"; else printf '%s\nset digest: %s\n' "$manifest" "$digest"; fi
