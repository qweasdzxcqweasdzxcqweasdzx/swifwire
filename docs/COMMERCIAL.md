# SwifWire — коммерческий self-hosted пакет (Windows)

Рабочий продукт: **свой протокол + edge-нода + клиентский SOCKS-core**.  
Не App Store VPN и не форк Xray — панель подключает `swif-edge` sidecar (см. [EMBED.md](EMBED.md)).

Документация: [INDEX.md](INDEX.md), [CLIENT_SDK.md](CLIENT_SDK.md), [SERVER_OPS.md](SERVER_OPS.md), [DOD.md](DOD.md), [../llms.txt](../llms.txt).

## Состав релиза

```powershell
.\scripts\release-win.ps1
# быстрая сборка без тестов: $env:SWIF_SKIP_GATE=1; .\scripts\release-win.ps1
```

В `dist/swifwire-win-x64/`:

| Файл | Роль |
|------|------|
| `swif-edge.exe` | Сервер / нода |
| `swif-core-run.exe` | Клиент (ядро + SOCKS) |
| `swif-pack.exe` | Подпись / verify mask packs |
| `swifwire.dll` + `include/swifwire.h` | Встройка (C ABI v1) |
| `swif-tray.exe` | Консольный start/stop |
| `deploy\*` | Prod/lab конфиги |
| `packs\*` | Пример signed pack + trust pub |
| `wintun.dll` | Опционально (OS TUN) |

## Прод на ноде

См. [deploy/edge.prod.example.md](../deploy/edge.prod.example.md). Кратко:

- Реальный `--cover` + `--tls-cert/--tls-key`
- **Без** `SWIF_LAB` / `SWIF_ALLOW_NULL` на публичных портах
- Клиент: `deploy/client.prod.example.json` (`tls_verify=webpki`, `legacy_fallback_uri`)

## Gate перед продажей / тестерами

```powershell
.\scripts\prod-gate.ps1
```

Чеклист:

- [x] Protocol+core smokes зелёные (`prod-gate`)
- [ ] Реальный cover-домен / сертификат (не lab self-signed)
- [ ] `null_tcp` выключен на публичных нодах
- [ ] Ключи `server.key` / `pack.key` только на сервере ops
- [ ] Клиентам раздан `pack.pub` (trust) + signed pack
- [ ] Host UI читает `legacy_fallback` из status / `swif_core_legacy_fallback_alloc`
- [ ] Мониторинг edge + лимиты в панели

## Честные ограничения

- Полный JA3/JA4 (порядок TLS-расширений) на rustls 0.23 **не** закрыт — см. HARDENING.
- Forged QUIC Initial — residual; `quic_stable` lab через `SWIF_ALLOW_QUIC_STABLE`.
- Системный TUN — feature `os-tun` + админ; по умолчанию SOCKS.
