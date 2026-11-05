# SwifWire edge — lab runbook

## Keys

```powershell
# first start creates server.key + server.pub (hex)
cargo run -p swif-edge -- --listen 127.0.0.1:9443 --mask null_tcp
```

Keep `server.key` offline. Distribute only `server.pub` to clients.

## Masks

| `--mask` | Underlay | Notes |
|----------|----------|-------|
| `null_tcp` | raw TCP | Dev only |
| `tls13_stable` | TLS 1.3 | Writes `lab-cert.der.json` for client pin |
| `quic_fast` | UDP cover | Thin QUIC-like header; lab only |

Failed inner auth on `tls13_stable` → builtin HTTP cover (or `--cover host:port`).

## Client

```powershell
cargo run -p swif-cli -- --server 127.0.0.1:9443 --pub-file server.pub --socks 127.0.0.1:11080 --mask null_tcp
# TLS:
cargo run -p swif-cli -- --server 127.0.0.1:9443 --pub-file server.pub --socks 127.0.0.1:11081 --mask tls13_stable --tls-material lab-cert.der.json
```

## Smoke

- `scripts/smoke-socks.ps1` — null_tcp
- `scripts/smoke-tls.ps1` — tls13_stable
- `scripts/smoke-udp.ps1` — DATAGRAM UDP map
- `scripts/perf-lab.ps1` — crude throughput vs direct

## UDP map

```powershell
# edge running, then:
.\target\debug\swif-cli.exe --server 127.0.0.1:9443 --pub-file server.pub --udp-ping 127.0.0.1:19000
```

## TUN

- Lab E2E (no admin): `.\scripts\smoke-tun.ps1` — NullTun L3 echo through edge.
- Fetch DLL: `.\scripts\fetch-wintun.ps1` → `third_party/wintun/wintun.dll` (+ copy to `target/debug`).
- OS TUN: `cargo build -p swif-cli --features os-tun` then (admin):
  `.\target\debug\swif-cli.exe --features…` / `cargo run -p swif-cli --features os-tun -- --tun --server … --pub-file server.pub`

## Tray / shell

- Console: `cargo run -p swif-tray -- --pub-file server.pub`
- WinForms icon: `scripts/tray-lab.ps1`

## Prod blockers

- Replace lab self-signed with real cover certs / SNI pool
- Pack signing keys in HSM / offline ceremony
- Do not ship `null_tcp` in release builds
- Bundle signed wintun + OS TUN UX
