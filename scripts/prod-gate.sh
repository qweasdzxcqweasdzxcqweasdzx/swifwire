#!/usr/bin/env bash
# Linux mirror of critical gate steps. Full SOCKS/TLS smokes are Windows-oriented in DOD.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export SWIF_ALLOW_NULL=1 SWIF_LAB=1 SWIF_ALLOW_QUIC_STABLE=1
echo "=== cargo test --workspace ==="
cargo test --workspace --quiet
echo "=== swif-ffi ==="
cargo build -p swif-ffi --quiet
echo "PROD GATE (linux partial) OK — run scripts/prod-gate.ps1 on Windows for full smoke/cover-probe"
