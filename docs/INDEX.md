# SwifWire — индекс документации

Единая точка входа для **разработчиков клиентов**, **панели/edge** и **нейросетей/агентов** на сервере.

| Если вы… | Читайте сначала |
|----------|-----------------|
| Пишете VPN / UI клиент | [CLIENT_SDK.md](CLIENT_SDK.md) |
| Поднимаете ноду / панель / sidecar | [SERVER_OPS.md](SERVER_OPS.md) |
| Агент/LLM на сервере (автоконфиг, ops) | [../llms.txt](../llms.txt) → [SERVER_OPS.md](SERVER_OPS.md) + JSON Schema |
| Разбираете wire / крипто | [WIRE.md](WIRE.md), [DESIGN.md](DESIGN.md) |
| Hardening / DPI gaps | [HARDENING.md](HARDENING.md) |
| Пакуете коммерческий Windows | [COMMERCIAL.md](COMMERCIAL.md) |
| Встраиваете в 3x-ui | [EMBED.md](EMBED.md) |

## Продукт в одном абзаце

**SwifWire** — свой транспорт: **Mask ∥ Session**. На проводе маска (`tls13_stable` / `quic_stable` lab / `quic_lab` / lab `null_tcp`), внутри **SwifHS v0** (X25519) + ChaCha20-Poly1305 + mux — **не** Noise_IK. Клиент поднимает локальный **SOCKS5** и dial’ит **swif-edge**. Это **не** VLESS/VMess/WireGuard и **не** модуль внутри Xray: edge — sidecar (как MTProto в 3x-ui).

## Артефакты репозитория

| Путь | Назначение |
|------|------------|
| `crates/swif-edge` | Сервер / нода `swif-edge` |
| `crates/swif-core` | Embed API + `swif-core-run` |
| `crates/swif-ffi` + `include/swifwire.h` | C ABI для клиентов |
| `bindings/go/swifwire` | Go helpers для панели |
| `schema/*.json` | JSON Schema (валидация конфигов) |
| `deploy/*.json` | Примеры inbound/client |
| `scripts/smoke-*.ps1` | Лабораторные проверки |
| `scripts/release-win.ps1` | Windows release zip |

## Машиночитаемые контракты

1. Подписка: `swif://host:port?pub=<64hex>&mask=tls13_stable&sni=…`
2. Клиентский конфиг ядра: [schema/core-config.v1.json](../schema/core-config.v1.json)
3. Outbound (панель/клиент): [schema/outbound.v1.json](../schema/outbound.v1.json)
4. Inbound (панель): [schema/inbound.v1.json](../schema/inbound.v1.json)
5. Status JSON: [schema/core-status.v1.json](../schema/core-status.v1.json)
6. Mask pack: [schema/mask-pack.v1.json](../schema/mask-pack.v1.json)
7. C ABI: [include/swifwire.h](../include/swifwire.h)

## Запреты / ограничения (важно и людям, и моделям)

- `null_tcp` — **только lab**: нужен `SWIF_ALLOW_NULL=1`. На публичных нодах — `tls13_stable` (или позже `quic_fast`).
- `server.key` (32 байта) — только на сервере; клиенту отдаётся только `server.pub` (64 hex).
- Не обещать «вечный обход DPI»; маски обновляются packs.
- Не подменять Xray целиком: SwifWire рядом, опциональный egress в SOCKS Xray.
