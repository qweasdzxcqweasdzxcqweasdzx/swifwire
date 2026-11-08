# Definition of Done

## `v0.1.0-mvp` / `v0.2.0` lab (frozen)

- [x] SOCKS via `null_tcp` / `tls13_stable` / core embed
- [x] Ticket resume &lt;2s; packs; UDP map; NullTun; tray
- [x] Commercial Windows pack + docs for client/server agents

## `v0.3.0-harden` (prod mask / probe-resistance)

See [HARDENING.md](HARDENING.md). Neutral goal: swappable mask + measurable cover parity — not “unblockable”.

- [x] WP0 gap table in HARDENING.md
- [x] SwifHS v0 specified in WIRE §4 (not claimed as Noise_IK)
- [x] `resume_fast` + `resume_fs` + wrong-key tests
- [x] Edge: `--cover` / `--cover-upstream` → `mirror_upstream`; `SWIF_LAB=1` for builtin
- [x] PEM `--tls-cert` / `--tls-key` load path
- [x] Client `tls_verify=pin|webpki` (webpki mode available; lab default pin)
- [x] Shaper idle Ping + min_pad + desktop/mobile profiles
- [x] DialPolicy in core runtime (no auto quic_lab unless `SWIF_ALLOW_QUIC_LAB=1`)
- [x] `scripts/smoke-probe-cover.ps1`
- [x] Pack-driven ALPN + named hello profile (`TlsPackHints`) — full JA3/uTLS still open
- [x] `quic_lab` grease DCID/version; `quic_stable` scaffold (`is_runtime_ready=false`)
- [x] `legacy_fallback_uri` config + dial-exhausted hint (host app executes legacy)
- [ ] Full browser ClientHello FP (uTLS-class) — WP2C remaining
- [ ] Quinn/pack `quic_stable` runtime — WP3 remaining
- [ ] cargo test + smoke-all green on release branch

## Tag (when harden DoD closed)

```powershell
git tag -a v0.3.0-harden -m "SwifWire cover-grade tls13_stable"
```
