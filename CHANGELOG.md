# Changelog

## Unreleased

- Embed API: inbound/outbound schemas, `swif://` shares
- C ABI `swif-ffi` (`include/swifwire.h`) for VPN clients
- Go helpers `bindings/go/swifwire` for 3x-ui-style sidecars
- Docs: `docs/EMBED.md`

## 0.1.0-mvp

Lab MVP frozen at VERSION `0.1.0-mvp`. Tag when OS TUN admin E2E checked: `git tag -a v0.1.0-mvp`.

## 0.1.0-mvp notes

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

Tag when DoD complete: `v0.1.0-mvp`.
