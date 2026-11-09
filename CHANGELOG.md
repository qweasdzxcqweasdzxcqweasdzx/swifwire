# Changelog

## Unreleased

## 0.5.0

Protocol/core **production** gate for SwifTun dual-stack integration:

- **Craft dial default** for chrome/firefox (`tls_craft_dial`); app secrets = CH…server Finished (RFC 8446); rustls only via fallback / `SWIF_TLS_RUSTLS_DIAL=1`
- Status: `prod_gate=0.5.0-prod`, `tls_extension_order_ready=true`, `craft_dial_wired=true`, `forge_ready=false`
- **Ticket master** required in prod (`--ticket-master` / `SWIF_TICKET_MASTER_HEX`); static-pub fallback only with `SWIF_LAB=1`
- JA4/JA3 lab corpus (`tests/vectors/ja4/`, `swif-pack ja3`) — pack-driven drift fixes
- QUIC forge **cut** from prod default (lab → 0.6); DialPolicy never silent-switches to quic
- Session `negative_hs` + REKEY/resume stress; crypto `fuzz_like` + vectors
- Edge metrics (handshake_ok / cover_path / rekey_ok); legacy contract doc
- ABI freeze: C ABI still **1**; status schema additive only
- Gate: `prod-gate.ps1` / `.sh` + `smoke-prod-0.5.ps1`

See [docs/RELEASE_0.5.0.md](docs/RELEASE_0.5.0.md).

## 0.4.0

Mass-client **production** gate for protocol + core (SwifTun):

- WP0 HARDENING gap table (file:line → residual → WP)
- WP1: `docs/CRYPTO.md`, `tests/vectors/`, PROTOCOL_CARD/llms/WIRE SwifHS sync (drop Noise_IK-like)
- WP2: prod edge requires PEM+cover; `prod-cover-probe.ps1`; partial JA3 label; extension_order still false
- WP3: `deploy/swif-edge.service`, edge ops
- WP4: DialPolicy honesty (quic_lab / quic_stable opt-in)
- WP5: reference host legacy execute contract
- WP6: `ffi/swifwire.udl` + MOBILE_FFI.md skeleton
- WP7: `docs/DUAL_STACK.md` phase1/2
- WP8: edge metrics counters; prod-gate expands; `prod-gate.sh` linux partial

**Residual → 0.5:** full JA3 extension order; forged Quinn Initial; UniFFI AAR/XCFramework; SBOM/Authenticode.

## 0.3.0

Production **test gate** for protocol + core (self-host commercial):

- **Prod gate:** `scripts/prod-gate.ps1` (workspace tests + smoke-all); release-win runs it by default
- **`swif-pack`:** gen-key / sign / verify / intent / sqi1
- **Core status:** `prod_gate`, `quic_stable_runtime_ready`, `tls_extension_order_ready=false`, legacy hint
- **C ABI:** `swif_core_legacy_fallback_alloc` (ABI version still 1)
- **Deploy:** `client.prod.example.json`, `edge.prod.example.md`
- Proto-4…7 + harden-1…3 folded in (SwifHS, REKEY, replay, quinn `quic_stable`, SQI1, pack hints)

## 0.2.0

Commercial Windows self-host package.

## 0.1.0-mvp

Lab MVP frozen.
