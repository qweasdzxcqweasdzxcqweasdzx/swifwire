# Сервер / панель / нейросеть на ноде — ops-гайд

Документ для оператора **и** для LLM-агента, который конфигурирует edge, панель и выдаёт подписки клиентам.

## 0. Контекст для модели

Прочитай сначала корневой [llms.txt](../llms.txt).  
Не генерируй VLESS/Reality UUID. Протокол панели: `"protocol": "swifwire"`.

## 1. Роли процессов

| Процесс | Где | Делает |
|---------|-----|--------|
| `swif-edge` | VPS / панель-хост | Слушает порт, mask cover, session, mux, egress |
| Панель (3x-ui fork и т.п.) | тот же хост | Хранит inbound JSON, supervisor lifecycle, биллинг |
| Xray (опционально) | тот же хост | Egress bridge через `socks5://127.0.0.1:…` |
| Клиент | устройство юзера | `swif-core` → SOCKS → edge |

## 2. Быстрый подъём ноды

```powershell
# Windows release unpack
.\swif-edge.exe --listen 0.0.0.0:443 --mask tls13_stable --key server.key --pub-out server.pub --sni cdn.example.com
# pub для клиентов:
Get-Content server.pub
```

```bash
# Linux (после сборки)
./swif-edge --listen 0.0.0.0:443 --mask tls13_stable --key /var/lib/swif/server.key --pub-out /var/lib/swif/server.pub --sni cdn.example.com
```

Флаги:

| Flag | Default | Meaning |
|------|---------|---------|
| `--listen` | `127.0.0.1:9443` | bind |
| `--key` | `server.key` | 32-byte secret (создаётся если нет) |
| `--pub-out` | `server.pub` | hex pubkey для клиентов |
| `--mask` | `tls13_stable` | wire appearance |
| `--sni` | `cover.local` | TLS SNI / material |
| `--cover` | none | upstream HTTP cover host:port |
| `--tls-material` | `lab-cert.der.json` | TLS cert/key material JSON |

**Lab:** `null_tcp` только с `SWIF_ALLOW_NULL=1`.

## 3. Inbound JSON (панель / агент)

Схема: [schema/inbound.v1.json](../schema/inbound.v1.json).  
Пример: [deploy/inbound.example.json](../deploy/inbound.example.json).

```json
{
  "protocol": "swifwire",
  "listen": "0.0.0.0",
  "port": 443,
  "tag": "swif-in",
  "remark": "SwifWire-443",
  "settings": {
    "static_key_path": "/var/lib/swif/server.key",
    "pub_out_path": "/var/lib/swif/server.pub",
    "mask": "tls13_stable",
    "sni": "cdn.example.com",
    "cover": "127.0.0.1:8443",
    "egress": "direct",
    "clients": [{ "email": "user1@swif", "enable": true }]
  }
}
```

Агент должен:

1. Валидировать JSON по schema.
2. Собрать argv через Go `EdgeArgv` или `swif_panel_edge_argv_alloc`.
3. Запустить/перезапустить sidecar.
4. Прочитать `server.pub` и выдать `swif://` клиенту.

## 4. Выдача подписки клиенту

```
swif://PUBLIC_HOST:443?pub=<contents of server.pub>&mask=tls13_stable&sni=cdn.example.com
```

Go: `ShareURI(publicHost, port, pubHex, mask, sni)`.  
C: `swif_panel_share_uri_alloc(...)`.

При ротации `server.key` — **все** клиентские URI устаревают; разошлите новый `pub`.

## 5. Egress

| `egress` | Поведение |
|----------|-----------|
| `direct` | edge сам ходит в интернет (текущий lab/prod default path) |
| `socks5://127.0.0.1:PORT` | мост в Xray outbound (панельная схема) |

Не удаляйте Xray «ради SwifWire» — держите рядом, если нужны чужие outbound’ы панели.

## 6. Cover / anti-probe (ops)

- Для `tls13_stable` настройте правдоподобный cover (свой origin или `--cover`).
- Невалидный handshake не должен «палиться» отличимым RST — см. [DESIGN.md](DESIGN.md) §probe.
- Lab self-signed OK для тестов; для продажи подписки — реальный домен/сертификат (чеклист [COMMERCIAL.md](COMMERCIAL.md)).

## 7. Чеклист действий агента (playbook)

```
TASK: provision_swifwire_node
1. Ensure dirs /var/lib/swif (or Windows deploy folder)
2. Write inbound JSON (mask=tls13_stable, no null_tcp)
3. Start swif-edge with EdgeArgv
4. Wait for server.pub
5. Build swif:// for each enabled client email/remark
6. Store URI in panel subscription export
7. Never log server.key
```

```
TASK: diagnose_client_fail
1. Confirm edge process up, listen port open
2. Confirm client pub matches server.pub
3. Confirm mask match (tls13_stable ↔ tls material)
4. Check SWIF_ALLOW_NULL only if mask=null_tcp
5. Run smoke-tls / smoke-core on lab mirror
```

## 8. Мониторинг (минимум)

- process alive `swif-edge`
- port listen
- disk: `server.key` permissions 0600
- optional: scrape edge logs (tracing `info`)

Счётчики per-client в core status пока упрощены (`bytes_up/down` на клиенте); биллинг панели — по своей модели `clients[]` (limit_ip, total_gb, expiry_time в inbound schema).

## 9. Связка с клиентским SDK

После выдачи URI клиент следует [CLIENT_SDK.md](CLIENT_SDK.md).  
Агент **не** должен подсовывать клиенту `server.key` или `null_tcp` в прод-подписках.

## 10. Тесты перед объявлением «нода готова»

- Windows lab: `.\scripts\smoke-all.ps1`
- Минимум: TLS smoke + core SOCKS HTTP 200
- Release: `.\scripts\release-win.ps1`
