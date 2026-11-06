# Agent / AI instructions for this repository

You are working on **SwifWire** (SwifTun transport). Read **[llms.txt](llms.txt)** first, then **[docs/INDEX.md](docs/INDEX.md)**.

## Hard rules

1. Treat `schema/*.json` as source of truth for config fields. Do not invent protocol names or Reality/VLESS fields.
2. Never commit or print `server.key` / private material. Clients get only `server.pub` (64 hex) via `swif://`.
3. Default mask is `tls13_stable`. `null_tcp` requires env `SWIF_ALLOW_NULL=1` and is lab-only.
4. Client product path = local SOCKS5 via `swif-core` / C ABI. Do not assume full OS TUN UX is shipped.
5. Edge is a **sidecar** binary (`swif-edge`), not an Xray inbound plugin.

## When generating configs

- Client: validate against `schema/core-config.v1.json` or `schema/outbound.v1.json`.
- Panel inbound: `schema/inbound.v1.json`.
- Status parsing: `schema/core-status.v1.json`.

## When changing code

- Keep C ABI in `include/swifwire.h` stable; bump carefully.
- Update `llms.txt` + relevant `docs/*.md` in the same change if contracts move.
- Run `cargo test --workspace` and on Windows `.\scripts\smoke-all.ps1` before claiming green.

## Primary human docs

| Audience | Doc |
|----------|-----|
| Client app developer | [docs/CLIENT_SDK.md](docs/CLIENT_SDK.md) |
| Server / panel / ops AI | [docs/SERVER_OPS.md](docs/SERVER_OPS.md) |
| Wire protocol | [docs/WIRE.md](docs/WIRE.md) |
