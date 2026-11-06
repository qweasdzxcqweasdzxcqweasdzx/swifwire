# SwifWire

Собственный транспорт **SwifTun**: Mask ∥ Session (не VLESS / не WireGuard).  
Клиент → локальный SOCKS5 → `swif-edge`. Панель держит edge как **sidecar**.

**Версия:** см. [VERSION](VERSION) · **Changelog:** [CHANGELOG.md](CHANGELOG.md)

## С чего начать

| Кто вы | Документ |
|--------|----------|
| Любой / навигация | **[docs/INDEX.md](docs/INDEX.md)** |
| Разработчик клиента (VPN UI) | **[docs/CLIENT_SDK.md](docs/CLIENT_SDK.md)** |
| Сервер / панель / нейросеть-агент | **[docs/SERVER_OPS.md](docs/SERVER_OPS.md)** + **[llms.txt](llms.txt)** |
| Cursor / coding agents | **[AGENTS.md](AGENTS.md)** |
| Wire / крипто | [docs/WIRE.md](docs/WIRE.md), [docs/DESIGN.md](docs/DESIGN.md) |
| 3x-ui embed | [docs/EMBED.md](docs/EMBED.md) |
| Windows commercial pack | [docs/COMMERCIAL.md](docs/COMMERCIAL.md) |

## Транспорт (кратко)

| Слой | Содержание |
|------|------------|
| Mask | `tls13_stable` (default), `quic_fast`, lab `null_tcp` |
| Session | Noise_IK-like X25519 → ChaCha20-Poly1305 AEAD + mux |
| Клиент UX | SOCKS5 (`swif-core` / C ABI); OS TUN — optional feature |

Подписка:

```
swif://vpn.example.com:443?pub=<64hex>&mask=tls13_stable&sni=cdn.example.com
```

## Машиночитаемые схемы

| Schema | Для чего |
|--------|----------|
| [schema/core-config.v1.json](schema/core-config.v1.json) | старт клиента |
| [schema/core-status.v1.json](schema/core-status.v1.json) | status JSON |
| [schema/outbound.v1.json](schema/outbound.v1.json) | outbound / embed |
| [schema/inbound.v1.json](schema/inbound.v1.json) | панель inbound |
| [schema/tls-material.v1.json](schema/tls-material.v1.json) | TLS cover material |
| [schema/mask-pack.v1.json](schema/mask-pack.v1.json) | signed mask packs |
| [include/swifwire.h](include/swifwire.h) | C ABI |

Примеры: [deploy/](deploy/).

## Сборка и проверки

```powershell
cargo test --workspace
.\scripts\smoke-all.ps1
.\scripts\release-win.ps1
```

```powershell
cargo run -p swif-edge -- --listen 0.0.0.0:9443 --mask tls13_stable --key server.key --pub-out server.pub
# подставьте pub в deploy/client.config.example.json
cargo run -p swif-core --bin swif-core-run -- client.config.json
curl.exe -x socks5h://127.0.0.1:10808 https://example.com/
```

`null_tcp` только с `SWIF_ALLOW_NULL=1` (lab).

## Репозиторий

https://github.com/qweasdzxcqweasdzxcqweasdzx/swifwire
