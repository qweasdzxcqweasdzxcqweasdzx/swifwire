# Changelog

## Unreleased

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

**Residual (documented):** full JA3 extension order; forged Quinn Initial; host executes legacy URI.

## 0.2.0

Commercial Windows self-host package:

- Live embed core SOCKS (`swif-core-run`, C ABI, Go sidecar helpers)
- Default mask `tls13_stable`; `null_tcp` requires `SWIF_ALLOW_NULL=1`
- Dial retries in core runtime; tray shell starts/stops `swif-core-run`
- `deploy/` examples, `docs/COMMERCIAL.md`, `scripts/release-win.ps1`, `scripts/smoke-all.ps1`
- VERSION / workspace `0.2.0`

## 0.1.0-mvp

Lab MVP frozen. Tag when OS TUN admin E2E checked: `git tag -a v0.1.0-mvp`.

### M1
- Wire framing, crypto, session, mux, shape
- `null_tcp` SOCKS tunnel (`swif-edge` / `swif-cli`)

### M2
- `tls13_stable` (rustls) + cover mirror
- `quic_fast` thin UDP cover
- Signed mask packs (ed25519)
- Ticket resume &lt;2s
- UniFFI-ready `swif-core` API

### M3
- MASK_OFFER / MASK_ACK / HEALTH
- DialPolicy fallback
- UDP map (DATAGRAM + `--udp-ping`)
- `swif-tun` NullTun + optional `os-tun` feature
- `swif-tray` minimal Windows tray
- EDGE_RUNBOOK, smoke scripts
