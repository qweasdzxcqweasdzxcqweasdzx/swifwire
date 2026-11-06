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
- [ ] Pack-driven ClientHello FP (uTLS / template order) — WP2C open
- [ ] Real `quic_stable` (not thin lab) — WP3 open
- [ ] Dual-stack legacy outbound hook — WP5/6 open
- [ ] cargo test + smoke-all green on release branch

## Tag (when harden DoD closed)

```powershell
git tag -a v0.3.0-harden -m "SwifWire cover-grade tls13_stable"
```
