# SwifWire

Собственный транспортный протокол и self-hosted edge/client для **SwifTun**.

| Документ | Назначение |
|----------|------------|
| [docs/COMMERCIAL.md](docs/COMMERCIAL.md) | Коммерческий пакет / релиз Windows |
| [docs/EMBED.md](docs/EMBED.md) | Встройка в 3x-ui и VPN-клиенты |
| [docs/DESIGN.md](docs/DESIGN.md) | Design doc |
| [docs/WIRE.md](docs/WIRE.md) | Wire format v0 |
| [docs/EDGE_RUNBOOK.md](docs/EDGE_RUNBOOK.md) | Edge ops |
| [CHANGELOG.md](CHANGELOG.md) | Releases |
| [schema/](schema/) | inbound / outbound / mask-pack |
| [include/swifwire.h](include/swifwire.h) | C ABI |
| [bindings/go/swifwire](bindings/go/swifwire) | Go sidecar helpers |

**Статус:** **`0.2.0`** — коммерческий Windows pack (SOCKS-core + edge). OS TUN — feature `os-tun` + admin.

```powershell
cargo test --workspace
.\scripts\smoke-all.ps1
.\scripts\release-win.ps1
```

```powershell
# прод-лаб (TLS mask)
cargo run -p swif-edge -- --listen 0.0.0.0:9443 --mask tls13_stable --key server.key --pub-out server.pub
# клиент: подставьте pub в deploy/client.config.example.json
cargo run -p swif-core --bin swif-core-run -- client.config.json
curl.exe -x socks5h://127.0.0.1:10808 https://example.com/
```

Lab-only `null_tcp` требует `SWIF_ALLOW_NULL=1`. Не цели: вечный обход DPI; замена Xray как единственного ядра панели.
