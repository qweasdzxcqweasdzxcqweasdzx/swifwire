# SwifWire

Собственный транспортный протокол и минимальное ядро для **SwifTun**.

| Документ | Назначение |
|----------|------------|
| [docs/DESIGN.md](docs/DESIGN.md) | Design doc |
| [docs/WIRE.md](docs/WIRE.md) | Wire format v0 |
| [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md) | 90-day plan |
| [docs/EDGE_RUNBOOK.md](docs/EDGE_RUNBOOK.md) | Edge ops |
| [CHANGELOG.md](CHANGELOG.md) | Releases |
| [docs/EMBED.md](docs/EMBED.md) | Встройка в 3x-ui и VPN-клиенты |
| [schema/](schema/) | inbound / outbound / mask-pack |
| [include/swifwire.h](include/swifwire.h) | C ABI |
| [bindings/go/swifwire](bindings/go/swifwire) | Go sidecar helpers |

**Статус:** **`0.1.0-mvp` lab** — DoD в [docs/DOD.md](docs/DOD.md). `wintun.dll` через `scripts/fetch-wintun.ps1`; live OS adapter — admin + `--features os-tun --tun`.

```powershell
cd swifwire
cargo test --workspace
.\scripts\smoke-socks.ps1
.\scripts\smoke-tls.ps1
.\scripts\smoke-udp.ps1
.\scripts\smoke-tun.ps1
.\scripts\smoke-core.ps1   # embed core live SOCKS
.\scripts\fetch-wintun.ps1
```

```powershell
cargo run -p swif-edge -- --listen 127.0.0.1:9443 --mask null_tcp
cargo run -p swif-cli -- --server 127.0.0.1:9443 --pub-file server.pub --socks 127.0.0.1:11080
cargo run -p swif-tray -- --pub-file server.pub   # console Start/Stop
# or: .\scripts\tray-lab.ps1
```

**Не цели:** вечный обход конкретного DPI; Xray/Reality как конечное ядро.
