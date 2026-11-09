# SwifWire v0.5.0 — protocol / core release notes

**Gate:** `0.5.0-prod` · **Tag:** `v0.5.0` · **C ABI:** still `1` (see [ABI_FREEZE.md](ABI_FREEZE.md))

## Ready for SwifTun dual-stack integration

| Area | Status |
|------|--------|
| Craft dial (chrome/firefox pack order) | **Default** · `tls_extension_order_ready=true` |
| rustls dial | Fallback / `SWIF_TLS_RUSTLS_DIAL=1` only |
| Edge prod | `--tls-cert/--tls-key/--cover` + **`--ticket-master`** (or env) required without `SWIF_LAB` |
| SOCKS product path | Stable; C ABI + `swif-core-run` |
| Legacy hint | Documented — host executes ([LEGACY_FALLBACK.md](LEGACY_FALLBACK.md)) |
| Status JSON | `prod_gate`, `tls_extension_order_ready`, `craft_dial_wired`, `forge_ready`, … |
| Edge metrics | `handshake_ok` / `cover_path` / `rekey_ok` (no secrets) |

## Lab-only (not prod default) → 0.6

| Area | Status |
|------|--------|
| QUIC forged Initial (`forge_ready`) | **false** — cut from prod default; `quic_stable` needs `SWIF_ALLOW_QUIC_STABLE=1` |
| `quic_lab` / `quic_fast` | Lab only |
| JA4 vs **real** Chrome capture parity | Corpus + pack workflow; not byte-identical to every Chrome build |
| UniFFI AAR/XCFramework | Skeleton only |
| Authenticode / mobile UI | Out of scope |

## Smoke (integrator)

```powershell
.\scripts\smoke-prod-0.5.ps1
# edge: PEM + cover + ticket-master  ↔  craft dial client  →  SOCKS HTTP 200
```

Full gate: `.\scripts\prod-gate.ps1` (Windows) / `./scripts/prod-gate.sh` (Linux tests).

## Artifacts

`scripts/release-win.ps1` → `dist/swifwire-win-x64/` (+ zip): edge, core-run, cli, tray, pack, dll+headers, deploy/, packs/, docs/, SBOM via `scripts/sbom.ps1`.
