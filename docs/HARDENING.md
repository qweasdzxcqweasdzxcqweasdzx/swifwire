# Hardening — `v0.3.0-prod`

Neutral goal: swappable mask + measurable cover parity — **not** “unblockable”.

## Status (2026-11-09)

| Area | State |
|------|--------|
| SwifHS v0 (not Noise_IK) | Done |
| Cover mirror + PEM | Done |
| webpki / pin verify | Done |
| Shaper idle + DialPolicy | Done |
| Ticket replay + REKEY | Done |
| Pack TLS hints + SQI1 | Done |
| quinn `quic_stable` lab | Done |
| Full uTLS extension order | **Residual** (needs craftls≥0.23 or dual stack) |
| Forged QUIC Initial | **Residual** |
| Host legacy dialer execution | **Host app** (URI exposed) |

## Prod node checklist

1. Real cover origin + cert (`--cover` + `--tls-cert/--tls-key`); no `SWIF_LAB` / `SWIF_ALLOW_NULL`.
2. Default mask `tls13_stable`; `quic_stable` only if explicitly lab-gated.
3. Client `tls_verify=webpki` with public CA cover cert (or pin to your leaf).
4. Signed mask pack via `swif-pack sign`; distribute trust pub to clients.
5. `.\scripts\prod-gate.ps1` green on the release binary set.
6. Configure `legacy_fallback_uri` for dual-stack UI; host dials it when status hints.

## Progress log

| Ver | Change |
|-----|--------|
| harden-1…proto-7 | See CHANGELOG Unreleased / 0.3.0 |
| 0.3.0-prod | prod-gate, swif-pack, legacy ABI, status readiness flags, deploy prod examples |
