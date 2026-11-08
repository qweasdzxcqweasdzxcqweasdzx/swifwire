# Changelog

## Unreleased

- **Proto-7:** pack `quic_initial`/SQI1 templates; lab cover grease/SCID/pad from pack; core `RuntimeHints` (tls+quic); `client_hello_intent` dump
- **Proto-6:** quinn `quic_stable` dial/accept + SOCKS lab path; DialPolicy prefers quic_stable over quic_lab; TLS sig-scheme preference + fingerprint budget docs; `smoke-quic-stable.ps1`
- **Proto-5:** edge ticket replay window; REKEY ack-before-advance (edge + core pump); pack hints hot-restart; `quic_stable` PrefStreamBuf framing bridge; WIRE §4.5 ordering
- **Proto-4:** rustls CryptoProvider cipher/kx profiles; `derive_rekey_keys` + session epoch/key_phase; CONTROL_EARLY; `TicketReplayWindow`; WIRE §3.1/§4.5–4.7
- **Harden-3:** pack `TlsPackHints`; greased `quic_lab`; `quic_stable` scaffold; `legacy_fallback_uri`
- **Harden-2:** `tls_verify` pin/webpki; shaper idle; DialPolicy; `smoke-probe-cover.ps1`
- **Harden-1:** SwifHS v0; resume_fs; cover mirror; PEM; `SWIF_LAB`
- Docs/schemas for client + server agents

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
