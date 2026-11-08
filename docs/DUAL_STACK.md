# Dual-stack: SwifWire + legacy (SwifTun phase 1→2)

## Invariant

SwifWire edge is a **sidecar** beside xray/sing-box Reality/HY2/cascade.  
Do **not** replace those inbounds in 0.4. Do **not** break VLESS share links.

## Phase 1 (mass clients)

1. Panel keeps existing Reality/HY2 share for `legacy_fallback_uri`.
2. Panel also publishes `swif://…` (schema/inbound + `swif_panel_share_uri_alloc`).
3. Client core dials SwifWire first (`tls13_stable`).
4. On exhaustion, core status / `swif_core_legacy_fallback_alloc` returns the legacy URI.
5. **Host app MUST execute** that URI (see `scripts/reference-host-legacy.ps1`).

## Phase 2

Prefer SwifWire when `prod_gate` / pack healthy; legacy remains escape hatch.

## Ports (example)

| Process | Port | Role |
|---------|------|------|
| xray Reality | 443 | legacy clients |
| swif-edge | 8443 (or 443 via SNI split) | SwifWire tls13_stable |
| cover origin | 8080 localhost | HTTP mirror for `--cover` |

SNI split on 443 is ops (nginx/haproxy); SwifWire does not terminate foreign Reality.

## Health

- `systemctl status swif-edge`
- Probe without pub → cover HTTP (no `SWI1`)
- Auth with pub → SOCKS 200
