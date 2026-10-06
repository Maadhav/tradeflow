#!/usr/bin/env bash
# Each CRE workflow compiles to its own WASM bundle, so the shared helpers are copied into
# every workflow directory. Edit cre/shared/lib.ts, then run this.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for w in listing lender settlement monitor; do cp "$ROOT/cre/shared/lib.ts" "$ROOT/cre/$w/lib.ts"; done
echo "synced lib.ts into listing, lender, settlement, monitor"
