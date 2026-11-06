# Встраивание SwifWire в 3x-ui и VPN-клиенты

Полные гайды: [CLIENT_SDK.md](CLIENT_SDK.md) (клиент), [SERVER_OPS.md](SERVER_OPS.md) (панель/edge), индекс [INDEX.md](INDEX.md), bootstrap для LLM: [../llms.txt](../llms.txt).

SwifWire **не внутри Xray**. Как MTProto в 3x-ui: отдельный sidecar + опциональный SOCKS bridge.

## Артефакты

| Что | Куда |
|-----|------|
| Ядро API | `crates/swif-core` |
| C ABI | `crates/swif-ffi` → `swifwire.dll` / `libswifwire.so` |
| Header | `include/swifwire.h` |
| Go (панель) | `bindings/go/swifwire` |
| Схемы | `schema/inbound.v1.json`, `schema/outbound.v1.json` |
| Edge binary | `swif-edge` |

```powershell
cargo build -p swif-ffi --release
cargo build -p swif-edge --release
# Windows: target\release\swifwire.dll + swif-edge.exe
```

## 3x-ui (панель)

### Модель

1. В inbound DB хранить JSON `protocol: "swifwire"` ([schema/inbound.v1.json](../schema/inbound.v1.json)).
2. Supervisor стартует `swif-edge` с argv из `EdgeArgv(inbound)` (Go) или `swif_panel_edge_argv_alloc`.
3. Клиентам отдавать `swif://…` через `ShareURI` / `swif_panel_share_uri_alloc`.
4. (Опционально) egress `socks5://127.0.0.1:<xray-socks>` — трафик уходит в Xray outbound.

### Пример inbound

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
    "clients": [{ "email": "u1@swif", "enable": true }]
  }
}
```

### Go

```go
import swifwire "github.com/qweasdzxcqweasdzxcqweasdzx/swifwire/bindings/go/swifwire"

in := swifwire.ExampleInbound(443, "/var/lib/swif/server.key")
sup := &swifwire.Supervisor{EdgeBin: "/usr/local/bin/swif-edge", WorkDir: "/var/lib/swif"}
_ = sup.Start(in)
uri := swifwire.ShareURI("vpn.example.com", 443, pubHex, "tls13_stable", "cdn.example.com")
```

Патч в форк 3x-ui: новый protocol enum + service по образцу `internal/mtproto/` (child process lifecycle).

## VPN-клиенты (iOS / Android / Windows / sing-box UI)

### Live runtime

`swif_core_start` / `core_start` поднимает **локальный SOCKS5** и на каждый CONNECT делает SwifWire dial к edge (`null_tcp` / `tls13_stable`).  
Проверка: `scripts/smoke-core.ps1`.

`start_runtime: false` — только конфиг/status (без сокета).

### C ABI

```c
#include "swifwire.h"
char *err = NULL;
const char *cfg =
  "{\"server_addr\":\"vpn.example.com:443\","
   "\"server_static_pub_hex\":\"…64 hex…\","
   "\"mask_profile\":\"tls13_stable\","
   "\"socks_listen\":\"127.0.0.1:10808\","
   "\"tls_material_path\":\"lab-cert.der.json\","
   "\"start_runtime\":true}";
if (swif_core_start(cfg, &err) != 0) { /* handle err */ swif_string_free(err); }
/* App routes traffic to local SOCKS 10808 — tunnel is live. */
char *st = swif_core_status_alloc(&err);
swif_string_free(st);
swif_core_stop();
```

### Подписка

```
swif://vpn.example.com:443?pub=<64hex>&mask=tls13_stable&sni=cdn.example.com
```

Импорт: `swif_core_import_subscription` / `core_import_subscription`.

### Outbound JSON

См. [schema/outbound.v1.json](../schema/outbound.v1.json) — можно класть рядом с VLESS/SS в своих клиентах.

## Что ещё не вшито автоматически

- Готовый PR в upstream 3x-ui (нужен форк + UI protocol picker).
- Полноценный TUN в мобильных сторах (сейчас SOCKS + NullTun; OS TUN — feature `os-tun`).
- UniFFI Swift/Kotlin codegen — C ABI уже стабилен как база.
