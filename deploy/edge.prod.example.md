# Production edge (tls13_stable) — v0.5.0

Do **not** set `SWIF_LAB=1` or `SWIF_ALLOW_NULL=1` on public nodes.

```powershell
# Generate ticket.master once (32 random bytes) and keep offline.
# [IO.File]::WriteAllBytes("ticket.master", (1..32 | ForEach-Object { Get-Random -Max 256 }))

.\swif-edge.exe `
  --listen 0.0.0.0:443 `
  --mask tls13_stable `
  --key C:\swif\server.key `
  --pub-out C:\swif\server.pub `
  --sni cdn.example.com `
  --tls-cert C:\swif\cover.crt `
  --tls-key C:\swif\cover.key `
  --cover 127.0.0.1:8443 `
  --ticket-master C:\swif\ticket.master
```

Or: `$env:SWIF_TICKET_MASTER_HEX="<64 hex>"`

## Required (prod)

| Flag / env | Meaning |
|------------|---------|
| `--tls-cert` / `--tls-key` | PEM cover cert |
| `--cover` | Live HTTP origin matching SNI |
| `--ticket-master` or `SWIF_TICKET_MASTER_HEX` | 32-byte ticket seal key (**not** static pub) |

## Not prod default

- `quic_stable` / `quic_lab` — lab only (`SWIF_ALLOW_QUIC_STABLE=1`); `forge_ready=false` until 0.6
- `null_tcp` — `SWIF_ALLOW_NULL=1` only

Client share: `swif://HOST:443?pub=<server.pub>&mask=tls13_stable&sni=cdn.example.com&tls_verify=webpki`
