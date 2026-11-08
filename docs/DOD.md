# Definition of Done

## `v0.3.0-prod` (frozen test gate)

- [x] Protocol + core commercial **lab** gate (`prod-gate` / smoke-all)
- See git tag `v0.3.0`

## `v0.4.0-prod` — mass-client production (this release)

Gate: `.\scripts\prod-gate.ps1` (includes `prod-cover-probe.ps1`).  
Linux: `scripts/prod-gate.sh` mirrors cargo test + notes Win-only smokes.

### A. Protocol / crypto
- [x] WIRE + PROTOCOL_CARD + llms synced to **SwifHS v0** (no Noise_IK-like)
- [x] `tests/vectors/` AEAD + KDF + CRYPTO.md
- [x] Matrix: wrong key / replay / REKEY (`prod_matrix` + handshake tests)
- [ ] Broader fuzz corpus (0.5 stretch)

### B. TLS cover-grade
- [x] Prod edge refuses start without `--tls-cert/--tls-key` + `--cover` (unless `SWIF_LAB=1`)
- [x] Pack chrome/firefox profiles + ALPN/GREASE/suites/sig (extension **order** still residual)
- [x] `prod-cover-probe.ps1` (no SWI1; timing log; auth SOCKS)
- [ ] `tls_extension_order_ready=true` — **blocked** until uTLS/craftls≥0.23 (residual → 0.5)
- [x] Ops: `deploy/edge.prod.example.md` + EDGE_RUNBOOK PEM/cover

### C. QUIC
- [x] DialPolicy: tls primary; quic_stable opt-in; quic_fast=`quic_lab`
- [x] Forged Initial residual documented (SQI1 policy only)

### D. Core / host / mobile
- [x] Legacy execute **contract** + `reference-host-legacy.ps1`
- [x] Mobile FFI skeleton `ffi/swifwire.udl` + MOBILE_FFI.md
- [x] Shaper desktop/mobile_idle already present

### E. Dual-stack
- [x] `docs/DUAL_STACK.md` + `deploy/swif-edge.service`
- [x] schema inbound / share URI unchanged (panel-compatible)

### F. Ops / release
- [x] Edge metrics log (handshake_ok / cover_path / rekey_ok) — no secrets
- [x] prod-gate expands cover-probe
- [x] HARDENING WP0 table; CHANGELOG; tag `v0.4.0`

## Residuals → 0.5 (frozen list from 0.4)

1. Full JA3/JA4 extension order (dual TLS / craftls backport)
2. Quinn forged Initial from capture
3. UniFFI AAR/XCFramework ship
4. SBOM + Windows Authenticode
5. Continuous fuzzing

## `v0.5.0` — cover-grade + mobile ship (in progress)

Gate: `prod-gate.ps1` + `swif-pack ja3` + `scripts/sbom.ps1`.

### A. TLS / JA3
- [x] Pack-driven ClientHello **wire encoder** (`tls_ch_wire`) + JA3 lab digests
- [x] Live craft dial default for chrome/firefox + rustls fallback (`SWIF_TLS_RUSTLS_DIAL=1`)
- [x] App-traffic AEAD parity vs rustls (`craft_dial_e2e`) → `tls_extension_order_ready=true`
- [ ] JA4_a/b against browser capture corpus (0.5 stretch)

### B. QUIC
- [x] Honest `forge_ready=false` + opaque inject scaffold
- [ ] Quinn accepts forged Initial / capture replay

### C. Crypto / supply chain
- [x] Property corpus (`fuzz_like`)
- [x] SBOM script (`scripts/sbom.ps1`)
- [ ] cargo-fuzz CI + Authenticode optional

### D. Mobile
- [x] UDL skeleton (0.4)
- [ ] UniFFI generate + Android AAR / iOS XCFramework CI artifacts

### E. Ops
- [ ] Cover probe timing band vs real CDN origin (optional env)
- [ ] Tag `v0.5.0` after green gate + craft dial or documented residual freeze
