#!/usr/bin/env bash
# Linux prod-gate: tests + craft e2e + vectors + ffi + sbom. Win-only smokes noted.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export SWIF_ALLOW_NULL=1 SWIF_LAB=1 SWIF_ALLOW_QUIC_STABLE=1
echo "=== cargo test --workspace ==="
cargo test --workspace --quiet
echo "=== craft dial e2e ==="
cargo test -p swif-mask --test craft_dial_e2e --quiet
echo "=== vectors / ja4 / negative_hs ==="
cargo test -p swif-crypto --test vectors --quiet
cargo test -p swif-mask --test ja4_corpus --quiet
cargo test -p swif-session --test negative_hs --quiet
echo "=== swif-ffi ==="
cargo build -p swif-ffi --quiet
echo "=== sbom ==="
bash scripts/sbom.sh || true
echo "PROD GATE (linux) OK — Win-only: smoke-all / smoke-prod-0.5 / prod-cover-probe via scripts/prod-gate.ps1"
