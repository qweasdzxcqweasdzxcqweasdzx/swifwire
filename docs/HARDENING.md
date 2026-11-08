# Hardening gap table — WP0 (`v0.3.0-harden`)

Source: DESIGN / WIRE vs code audit (0.2.0).  
Goal language: measurable cover / probe-resistance, swappable masks — **not** “unblockable”.

## Gap table

| DESIGN claim | Code | Gap | Owner | Breaking? |
|--------------|------|-----|-------|-----------|
| Noise_IK inner HS | `swif-session/src/handshake.rs` | Custom X25519+SHA256 proofs («SwifHS»), not `snow`/Noise_IK | WP1 | Yes if migrate to Noise |
| Pack-driven TLS ClientHello | `swif-mask/src/tls13.rs`, `pack.rs` | rustls default FP; pack templates unused | WP2 | Yes (wire FP) |
| Cover = live origin mirror | `swif-edge` `handle_tls`; `cover.rs` | `--cover` ignored; only `serve_builtin_http`; `mirror_to_upstream` unused | WP2 | No |
| Real cert / chain | `tls13.rs` `LabTlsMaterial` | JSON hex / rcgen only; no PEM ingest | WP2 | No |
| Client trust = webpki | `connector_pin` | Pin-only (lab) | WP2 | No (add mode) |
| quic_fast ≈ QUIC | `quic_fast.rs` | Thin long-header + len-pref; fixed `COVER_VERSION`/`DCID_LEN` | WP3 | Yes → rename `quic_lab` |
| Probe corpus vs cover | `probe.rs` | HTTP prefix check only | WP2/WP7 | No |
| Shaper `on_idle` | `swif-shape`; `transport.rs` | `wrap` used; `on_idle` never called | WP4 | No |
| Ticket resume + fresh eph | `handshake.rs` resume | `eph_pub=[0;32]`, no FS (`resume_fast` only) | WP1 | Yes for `resume_fs` |
| CONTROL_EARLY / replay bloom | ticket comments | Not implemented | WP1 later | Yes |
| DialPolicy fallback | `policy.rs` vs `runtime.rs` | Policy unused on dial path | WP5 | No |
| Dual-stack legacy | docs only | No client legacy outbound hook | WP5/WP6 | No |

## Breaking vs non-breaking

**Breaking (needs version / explicit mode):** Noise_IK migration; `resume_fs` wire; pack-driven CH templates; real QUIC mask replacing thin cover.

**Non-breaking (ship first):** wire `--cover` → `mirror_to_upstream`; PEM load; `SWIF_LAB` prod guard; formalize **SwifHS v0** + vectors; rename thin UDP → `quic_lab` in docs/policy; shaper idle; DialPolicy wiring.

## Decision freeze (WP0)

1. **Handshake:** keep wire-compatible **SwifHS v0** (documented in WIRE §4); Noise_IK/`snow` = optional `v1` under version bump (not this pass).
2. **Resume:** expose `resume_fast` (current) and `resume_fs` (fresh eph); default API = `resume_fast` until mobile policy opts in.
3. **Default mask:** `tls13_stable`; thin UDP documented as **`quic_lab`** (alias of `quic_fast` id until WP3 profile).
4. **Prod TLS edge:** require cover upstream **or** `SWIF_LAB=1`.

## Prod-hardening DoD → see `docs/DOD.md` section `v0.3.0-harden`

## Progress log

| Date | Change |
|------|--------|
| 0.2.x harden-1 | SwifHS v0 spec; resume_fs; cover mirror; PEM; SWIF_LAB |
| 0.2.x harden-2 | webpki verify mode; shaper idle/min_pad; DialPolicy runtime; smoke-probe-cover |
| 0.2.x harden-3 | pack ALPN/`chrome_stable` hints via rustls; quic_lab grease; `quic_stable` scaffold; `legacy_fallback_uri` |

**Still open:** full JA3/JA4 uTLS; quinn-backed `quic_stable` runtime; host-app execution of legacy URI.
