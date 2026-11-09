# ABI / schema freeze — v0.5.0

## C ABI (`include/swifwire.h`)

| Symbol | Status |
|--------|--------|
| `swif_abi_version` | **1** (unchanged from 0.3/0.4) |
| `swif_core_*` / `swif_panel_*` / `swif_string_free` | stable |

No C symbol added/removed in 0.5.0 → **no ABI bump**.  
Next bump only when a signature changes or a symbol is removed.

## JSON schemas (`schema/*.json`)

| Schema | 0.5 change |
|--------|------------|
| `core-status.v1.json` | **Additive** optional fields: `tls_extension_order_ready`, `craft_dial_wired`, `quic_stable_runtime_ready`, `forge_ready`, `prod_gate` |
| `core-config.v1.json` | unchanged |
| `outbound.v1.json` / `inbound.v1.json` | unchanged |
| `mask-pack.v1.json` | unchanged |

Hosts must ignore unknown status fields. Required keys unchanged.

## Semver

- **0.5.0** — protocol/core production gate (craft dial default).
- Breaking wire/session changes require `PROTOCOL_VERSION` / record nibble bump + WIRE.md (not done in 0.5).
