# Hardening gap table — toward `v0.5.0`

Neutral goal: measurable cover parity, fast mask-pack swap, dual-stack migration, stable SOCKS path — **not** “unblockable TSPU/GFW”.

## WP0 — claim → code → residual → target

| # | Claim / need | Code (file:line) | 0.3.0 state | Residual | Target WP |
|---|--------------|------------------|-------------|----------|-----------|
| R1 | Chrome-like ClientHello extension order (JA3/JA4) | `tls_craft_dial` default; `craft_dial_e2e` green; status ready=true | Done for chrome/firefox | JA4 capture corpus; full browser parity | 0.5 JA4 |
| R2 | Quinn forged Initial | `quic_initial.rs` SQI1; `quic_stable.rs` quinn dial; `forge_ready=false` | Cut from prod default | Inject into quinn | **0.6** |
| R3 | Host **executes** legacy URI | `swifwire.h:36` alloc; `lib.rs:220` getter; status hint | Hint only | No reference host dialer | WP5 |
| R4 | Dual-stack beside xray | docs only; edge sidecar | Docs thin | No systemd/panel contract pack | WP7 |
| R5 | Mobile UniFFI ship | C ABI only `swif-ffi` | None | No udl/AAR/XCFramework | WP6 skeleton |
| R6 | Real cover cert + probe≈origin | `edge/main.rs` `load_tls_material` + `cover_mode_for`; `prod-cover-probe.ps1` | Lab builtin OK | Real CDN timing-band vs origin still ops-owned | WP2/WP3 done (PEM hard); 0.5 CDN suite |
| R7 | Crypto vectors / fuzz | `tests/vectors/` + `CRYPTO.md` + `prod_matrix` | Done for 0.4 | Continuous fuzz corpus | WP1 done; fuzz → 0.5 |
| R8 | Edge metrics (no secrets) | `EdgeMetrics` handshake_ok/cover_path/rekey_ok | Counters logged | Prometheus export optional | WP8 done |
| R9 | Release discipline | `prod-gate.ps1` + `.sh`; VERSION 0.4.0 | Gate expanded | SBOM / Authenticode | WP8; SBOM → 0.5 |
| — | SwifHS ≠ Noise_IK | `handshake.rs`; WIRE §4; PROTOCOL_CARD; llms | Synced | DESIGN historical Noise wording patched | WP1 done |
| — | Default mask tls13_stable | edge/cli/core defaults | OK | — | keep |
| — | Magic SWI1 only inside mask | `wire/lib.rs:20-22`; cover path | OK | — | keep |
| — | Ticket replay | `handshake.rs:271+`; edge Mutex | OK | — | keep |
| — | REKEY ack-before-advance | edge `post_handshake_loop`; WIRE §4.5 | OK | — | keep |
| — | quic_fast demoted | policy `QuicLab`; not DialPolicy default | OK | Rename messaging quic_lab | WP4 |

## Prod node checklist (unchanged intent)

1. Real `--cover` + `--tls-cert/--tls-key`; no `SWIF_LAB` / `SWIF_ALLOW_NULL`.
2. Default mask `tls13_stable`; quic_* only with explicit lab flags.
3. Client `tls_verify=webpki` (or pin to your leaf).
4. Signed pack + trust pub to clients.
5. `prod-gate` + `prod-cover-probe` green.
6. Host executes `legacy_fallback_uri` when hinted (WP5).

## Progress log

| Ver | Change |
|-----|--------|
| 0.3.0-prod | test gate, swif-pack, legacy hint ABI, quinn lab |
| 0.4.0 | WP0–WP8: vectors/CRYPTO; PEM+cover hard; cover-probe; DialPolicy; legacy host; UniFFI skeleton; dual-stack docs; metrics; gate |
| 0.5.0-wip | tls_ch_wire + craft_dial module; ticket-master; negative_hs; DialPolicy quic opt-in |
| 0.5.0 | craft default + e2e; JA4 corpus; ticket prod-hard; QUIC forge cut; prod_gate 0.5.0-prod; tag v0.5.0 |
