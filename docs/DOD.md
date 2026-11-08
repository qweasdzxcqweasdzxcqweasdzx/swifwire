# Definition of Done

## `v0.1.0-mvp` / `v0.2.0` lab (frozen)

- [x] SOCKS via `null_tcp` / `tls13_stable` / core embed
- [x] Ticket resume &lt;2s; packs; UDP map; NullTun; tray
- [x] Commercial Windows pack + docs for client/server agents

## `v0.3.0-prod` — protocol + core ready for commercial tests

Gate: `.\scripts\prod-gate.ps1` (cargo test + smoke-all).

- [x] SwifHS v0 + resume_fast/fs + replay window + REKEY
- [x] `tls13_stable` cover mirror + PEM; `tls_verify=pin|webpki`
- [x] `quic_stable` quinn lab path + pack SQI1/`quic_initial`
- [x] DialPolicy + `legacy_fallback_uri` surfaced to host (`core_legacy_fallback_*`)
- [x] Pack hot-apply (`RuntimeHints` tls+quic); `swif-pack` CLI
- [x] C ABI v1 stable (+ legacy fallback alloc); status `prod_gate=0.3.0-prod`
- [x] `scripts/smoke-all.ps1` green
- [x] `scripts/prod-gate.ps1` + release-win runs gate by default
- [x] Deploy prod examples (`deploy/client.prod.example.json`, `edge.prod.example.md`)

### Known residuals (not blocking self-host prod tests)

- [ ] Full JA3/JA4 ClientHello extension order (rustls 0.23; craftls stuck on 0.22)
- [ ] Quinn forged Initial from opaque browser capture
- [ ] Host app must **execute** `legacy_fallback_uri` (core only exposes hint)
- [ ] OS TUN / App Store UI — product layer outside this gate

## Tag

```powershell
.\scripts\prod-gate.ps1
git tag -a v0.3.0 -m "SwifWire protocol+core production test gate"
```
