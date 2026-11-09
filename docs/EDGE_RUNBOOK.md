# SwifWire edge — runbook

## Keys

```powershell
# first start creates server.key + server.pub (hex)
$env:SWIF_LAB=1
cargo run -p swif-edge -- --listen 127.0.0.1:9443 --mask tls13_stable
```

Keep `server.key` offline. Distribute only `server.pub` to clients.

## Prod TLS (cover-grade)

```powershell
.\swif-edge.exe `
  --listen 0.0.0.0:443 `
  --mask tls13_stable `
  --key server.key --pub-out server.pub `
  --sni cdn.example.com `
  --tls-cert cover.crt --tls-key cover.key `
  --cover-upstream 127.0.0.1:8443 `
  --ticket-master ticket.master
```

| Flag | Meaning |
|------|---------|
| `--cover` / `--cover-upstream` | After TLS terminate, failed/probe path mirrors bytes to this HTTP origin |
| `--tls-cert` / `--tls-key` | PEM cover cert (required for prod; JSON lab material needs `SWIF_LAB=1`) |
| `--ticket-master` / `SWIF_TICKET_MASTER_HEX` | 32-byte ticket seal (prod required; static-pub fallback only with `SWIF_LAB=1`) |
| `SWIF_LAB=1` | Allow self-signed JSON material + builtin HTML cover + static-pub ticket |

Without cover upstream and without `SWIF_LAB`, `tls13_stable` **refuses to start**.  
Prod (no `SWIF_LAB`) also requires **PEM + ticket-master** (JSON lab material / static-pub ticket rejected).

## Masks

| `--mask` | Underlay | Notes |
|----------|----------|-------|
| `tls13_stable` | TLS 1.3 | **Default / prod** |
| `quic_fast` / `quic_lab` | thin UDP | Lab only; not DialPolicy default |
| `null_tcp` | raw TCP | `SWIF_ALLOW_NULL=1` only |

## Client

```powershell
cargo run -p swif-cli -- --server 127.0.0.1:9443 --pub-file server.pub --socks 127.0.0.1:11081 --mask tls13_stable --tls-material lab-cert.der.json
# core JSON: "tls_verify": "pin" | "webpki"
```

## Smoke

- `scripts/smoke-tls.ps1` — auth path
- `scripts/smoke-probe-cover.ps1` — probe gets cover, auth SOCKS OK
- `scripts/smoke-all.ps1` — full lab suite (`SWIF_LAB=1`)

## TUN / tray

- NullTun: `scripts/smoke-tun.ps1`
- OS TUN: `--features os-tun` + admin + `fetch-wintun.ps1`
- Tray: `swif-tray` / `scripts/tray-lab.ps1`

## Hardening

See [HARDENING.md](HARDENING.md). Shaper idle Ping is on; pack-driven ClientHello FP still open.
