# Definition of Done — `v0.1.0-mvp`

## Must (lab green)

- [x] SOCKS TCP via `null_tcp` — `scripts/smoke-socks.ps1`
- [x] SOCKS TCP via `tls13_stable` — `scripts/smoke-tls.ps1`
- [x] Cover mirror on auth fail
- [x] `quic_fast` UDP cover unit + dial
- [x] Signed mask pack load
- [x] Ticket resume &lt;2s (+ reconnect suite)
- [x] MASK_OFFER / ACK / HEALTH
- [x] DialPolicy
- [x] UDP map — `scripts/smoke-udp.ps1`
- [x] TUN L3 path (NullTun echo) — `scripts/smoke-tun.ps1`
- [x] Optional OS TUN API (`--features os-tun` + `fetch-wintun.ps1`)
- [x] Tray/console shell — `swif-tray` / `tray-lab.ps1`
- [x] EDGE_RUNBOOK + CHANGELOG

## Ops before public tag

- [ ] Place `wintun.dll` via `scripts/fetch-wintun.ps1`
- [ ] Admin machine: `cargo run -p swif-cli --features os-tun -- --tun …` shows `OS_TUN OPEN OK`
- [ ] Perf lab ≥70% on quiet LAN (`scripts/perf-lab.ps1`) — informational

## Tag command

```powershell
git tag -a v0.1.0-mvp -m "SwifWire lab MVP"
```
