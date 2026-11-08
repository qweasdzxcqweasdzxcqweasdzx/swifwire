# Клиентский SDK — гайд для разработчика приложения

Цель: встроить SwifWire в Windows / Android / iOS / desktop UI так, чтобы приложение поднимало туннель и гнало трафик через локальный SOCKS5.

## 1. Модель (обязательно понять)

```
[App / system proxy]
        │  SOCKS5 CONNECT
        ▼
[swif-core / swifwire.dll] ── Mask dial ──► [swif-edge]
        │                                      │
        └──── Session AEAD + mux streams ──────┘
```

- Приложение **не** говорит на VLESS.
- Приложение линкует **C ABI** (или вызывает `swif-core-run`) и роутит трафик на `socks_listen` (по умолчанию `127.0.0.1:10808`).
- Подписка — URI `swif://…`.

## 2. Артефакты для сборки клиента

| Платформа | Что брать |
|-----------|-----------|
| Windows | `swifwire.dll` + `include/swifwire.h` из `scripts/release-win.ps1` |
| Другие | `cargo build -p swif-ffi --release` → `libswifwire` |
| Без native | JSON-конфиг + внешний процесс `swif-core-run` |

Версия ABI: `swif_abi_version()` из header.

## 3. Подписка `swif://`

```
swif://vpn.example.com:443?pub=<64hex>&mask=tls13_stable&sni=cdn.example.com
```

| Параметр | Обязателен | Описание |
|----------|------------|----------|
| host:port | да | адрес edge |
| `pub` | да | 64 hex — static public key сервера |
| `mask` | нет | default `tls13_stable` |
| `sni` | нет | cover SNI |

Импорт в рантайме: `swif_core_import_subscription` / Rust `core_import_subscription`.

Парсинг без native: разберите query; `pub` длина ровно 64.

## 4. Конфиг старта (flat JSON)

Минимум:

```json
{
  "server_addr": "vpn.example.com:443",
  "server_static_pub_hex": "0123…64 hex…",
  "mask_profile": "tls13_stable",
  "socks_listen": "127.0.0.1:10808",
  "tls_material_path": "path/to/tls-material.json",
  "start_runtime": true,
  "route_mode": "global"
}
```

Схема: [schema/core-config.v1.json](../schema/core-config.v1.json).  
Пример: [deploy/client.config.example.json](../deploy/client.config.example.json).

### TLS material (для `tls13_stable`)

Файл JSON:

```json
{
  "sni": "cdn.example.com",
  "cert_hex": "…",
  "key_hex": "…"
}
```

В lab его генерирует edge при первом старте (`lab-cert.der.json`). В проде клиенту нужен согласованный cover/trust path — не путать с `server.pub` (это ключ SwifWire session, не TLS cert).

## 5. C API — типовой lifecycle

```c
#include "swifwire.h"

char *err = NULL;
const char *cfg = "{ ... core-config json ... }";

if (swif_core_start(cfg, &err) != 0) {
  /* показать err пользователю */
  swif_string_free(err);
  return;
}

/* UI: «подключено» если status.state == running и SOCKS слушает */
char *st = swif_core_status_alloc(&err);
/* parse JSON → schema/core-status.v1.json */
swif_string_free(st);

/* трафик приложения / VpnService → 127.0.0.1:10808 */

swif_core_stop();
```

Правила памяти: **каждый** ненулевой `char*` из `*_alloc` / `err_out` — `swif_string_free`.

Полный список: [include/swifwire.h](../include/swifwire.h).

## 6. Status JSON

Пример:

```json
{
  "state": "running",
  "mask": "tls13_stable",
  "pack_id": null,
  "route_mode": "global",
  "socks_listen": "127.0.0.1:10808",
  "server": "vpn.example.com:443",
  "bytes_up": 0,
  "bytes_down": 0,
  "last_error": null
}
```

`state`: `running` | `started` (без runtime) | `stopped`.

## 7. Маски — что выбирать в UI

| Mask | Когда |
|------|--------|
| `tls13_stable` | **Прод по умолчанию** (TCP/TLS cover) |
| `quic_fast` | UDP cover; в core SOCKS путь может быть ограничен — проверяйте релиз |
| `null_tcp` | Только lab / отладка; на клиенте тоже нужен `SWIF_ALLOW_NULL=1` |

## 8. Роутинг трафика в приложении

1. **Простой путь:** системный / in-app SOCKS proxy → `socks_listen`.
2. **VPN mode (TUN):** ваш OS VpnService/WFP → userspace → SOCKS или будущий os-tun. Сейчас продуктово гарантирован SOCKS.
3. `route_mode` хранится в core (`global` и т.д.); полноценный split-routing — зона UI + будущие политики.

## 9. Mask packs

`swif_core_apply_mask_pack(bytes, len)` — signed pack (ed25519). Схема: [schema/mask-pack.v1.json](../schema/mask-pack.v1.json).  
Trust key: `pack_trust_pub_hex` в конфиге.

## 10. Проверка интеграции

```powershell
# на машине с собранным edge+core
$env:SWIF_ALLOW_NULL="1"   # только если тестируете null
.\scripts\smoke-core.ps1
```

Ожидание: HTTP 200 через SOCKS core.

## 10b. Dual-stack (phase 1)

В конфиге можно указать opaque `legacy_fallback_uri` (например share другой транспорт).  
SwifWire **не** исполняет его: при исчерпании dial retries ошибка содержит `legacy_fallback_hint=…` — UI переключает outbound сам.

Pack: `templates.client_hello_profile` (`chrome_stable` / `firefox_stable` / `rustls_default`) + `alpn` применяются через rustls ALPN. Полный JA3/uTLS ещё не закрыт.

`quic_stable` в pack — scaffold; `PrefStreamBuf` framing for future QUIC stream 0 ready; `is_runtime_ready=false` until quinn. Lab UDP = `quic_lab` / `quic_fast` + `SWIF_ALLOW_QUIC_LAB`.

## 11. Частые ошибки

| Симптом | Причина |
|---------|---------|
| start fails на null_tcp | нет `SWIF_ALLOW_NULL=1` |
| TLS dial fail | неверный/отсутствует `tls_material_path` или SNI/cover |
| pub length error | `server_static_pub_hex` не 64 hex |
| порт занят | другой процесс на `socks_listen` |
| «работает cli, не dll» | забыли `start_runtime: true` или не роутите на SOCKS |

## 12. Связанные документы

- Встройка в панель: [EMBED.md](EMBED.md)
- Wire: [WIRE.md](WIRE.md)
- Коммерческий пакет: [COMMERCIAL.md](COMMERCIAL.md)
