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
- [ ] Pack-driven ClientHello FP (uTLS / template order) — WP2C open
- [ ] Client webpki roots prod default — WP2B open
- [ ] `quic_lab` rename + real `quic_stable` — WP3 open
- [ ] Shaper `on_idle` wired — WP4 open
- [ ] DialPolicy drives runtime fallback — WP5 open
- [ ] `scripts/smoke-probe-cover.ps1` probe≈cover harness — WP2E open
- [ ] cargo test + smoke-all green on release branch

## Tag (when harden DoD closed)

```powershell
git tag -a v0.3.0-harden -m "SwifWire cover-grade tls13_stable"
```
