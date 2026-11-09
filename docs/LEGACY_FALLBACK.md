# Legacy fallback contract (host executes)

SwifWire **never dials** the legacy share. The host VPN UI / tray / Happ wrapper does.

## Config

Opaque string on outbound / core config:

```json
"legacy_fallback_uri": "vless://UUID@host:443?encryption=none&security=reality&…"
```

Any URI scheme the host understands is fine (`vless://`, `hy2://`, `ss://`, …). SwifWire treats it as opaque.

## When core surfaces the hint

1. Config has `legacy_fallback_uri` set.
2. `tls13_stable` dial retries are **exhausted** (default 3 attempts with DialPolicy backoff).
3. Core does **not** silently switch to QUIC (quic is opt-in via `SWIF_ALLOW_QUIC_STABLE` / explicit mask only).

Then:

| Channel | Behavior |
|---------|----------|
| Status JSON | `legacy_fallback_hint` = configured URI (also present at start from config) |
| `last_error` | contains `legacy_fallback_hint=<uri>` |
| C ABI | `swif_core_legacy_fallback_alloc` returns the URI string (empty if unset) |

## Host duty

```
uri = status.legacy_fallback_hint  // or ABI alloc
if dials_exhausted && uri:
    EXECUTE uri with legacy stack (xray / sing-box / …)
```

Reference print-only sample: `scripts/reference-host-legacy.ps1`.
