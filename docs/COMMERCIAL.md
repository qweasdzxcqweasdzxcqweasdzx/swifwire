# SwifWire — коммерческий self-hosted пакет (Windows)

Рабочий продукт: **свой протокол + edge-нода + клиентский SOCKS-core**.  
Не App Store VPN и не форк Xray — панель подключает `swif-edge` sidecar (см. [EMBED.md](EMBED.md)).

Документация для интеграторов и серверных агентов: [INDEX.md](INDEX.md), [CLIENT_SDK.md](CLIENT_SDK.md), [SERVER_OPS.md](SERVER_OPS.md), [../llms.txt](../llms.txt).

## Состав релиза

Собрать:

```powershell
.\scripts\release-win.ps1
```

В `dist/swifwire-win-x64/`:

| Файл | Роль |
|------|------|
| `swif-edge.exe` | Сервер / нода |
| `swif-core-run.exe` | Клиент (ядро + SOCKS) |
| `swifwire.dll` + `swifwire.h` | Встройка в приложения |
| `swif-tray.exe` | Консольный start/stop |
| `deploy\*.json` | Примеры конфигов |
| `wintun.dll` | Опционально (OS TUN) |

## Быстрый прод-лаб на одной машине

```powershell
# 1) edge (TLS mask)
$env:SWIF_ALLOW_NULL="1"   # только если тестируете null_tcp
.\swif-edge.exe --listen 0.0.0.0:9443 --mask tls13_stable --key server.key --pub-out server.pub

# 2) клиент — подставить pub из server.pub в config.json
.\swif-core-run.exe client.config.json

# 3) трафик
curl.exe -x socks5h://127.0.0.1:10808 https://example.com/
```

Подписка клиенту: `swif://YOUR_IP:9443?pub=<hex>&mask=tls13_stable&sni=cdn.example.com`

## 3x-ui

См. [EMBED.md](EMBED.md): Go `Supervisor` + inbound JSON. Xray не заменяется — edge рядом.

## Ограничения честно

- Системный TUN/маршруты — feature `os-tun` + админ; по умолчанию SOCKS (браузер/приложения через прокси или системный SOCKS helper).
- DPI «навсегда» не гарантируется; маски и packs обновляемые.
- iOS/Android store UI — отдельно на C ABI.

## Чеклист перед продажей подписки

- [ ] Реальный cover-домен / сертификат (не lab self-signed)
- [ ] `null_tcp` выключен на публичных нодах
- [ ] Ключи `server.key` только на сервере
- [ ] Мониторинг edge + лимиты клиентов в панели
- [ ] `.\scripts\smoke-all.ps1` зелёный на вашей сборке
