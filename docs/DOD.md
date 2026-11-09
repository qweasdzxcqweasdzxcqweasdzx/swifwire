# Definition of Done

## `v0.5.0` — protocol/core production (this release)

Gate: `.\scripts\prod-gate.ps1` · Linux: `scripts/prod-gate.sh`  
Integrator smoke: `.\scripts\smoke-prod-0.5.ps1` (PEM+cover+ticket-master ↔ craft dial → SOCKS 200)

### Freeze
- [x] Craft dial default chrome/firefox; rustls only `SWIF_TLS_RUSTLS_DIAL=1` / fallback
- [x] Status honest: `prod_gate=0.5.0-prod`, `tls_extension_order_ready`, `craft_dial_wired`, `forge_ready=false`
- [x] JA4 corpus + pack workflow (`tests/vectors/ja4/`, `swif-pack ja3`)
- [x] QUIC forge cut from prod default (lab → 0.6)
- [x] Ticket master prod-hard; static-pub only with `SWIF_LAB`
- [x] Session negatives + REKEY/resume stress in gate
- [x] ABI freeze C=`1`; status schema additive ([ABI_FREEZE.md](ABI_FREEZE.md))
- [x] Legacy contract ([LEGACY_FALLBACK.md](LEGACY_FALLBACK.md))
- [x] Release notes ([RELEASE_0.5.0.md](RELEASE_0.5.0.md))
- [x] Tag `v0.5.0`

### Lab / later
- [ ] Real Chrome capture JA4 byte-parity (pack iteration)
- [ ] `forge_ready=true` Quinn Initial inject (0.6)
- [ ] UniFFI AAR/XCFramework
- [ ] Authenticode

## `v0.4.0-prod` (frozen)

See tag `v0.4.0`.

## `v0.3.0-prod` (frozen)

See tag `v0.3.0`.
