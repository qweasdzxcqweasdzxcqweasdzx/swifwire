# Changelog

## Unreleased

- Docs for client developers + server/LLM agents: `docs/INDEX.md`, `CLIENT_SDK.md`, `SERVER_OPS.md`, `llms.txt`, `AGENTS.md`
- Schemas: `core-config.v1`, `core-status.v1`, `tls-material.v1`

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
