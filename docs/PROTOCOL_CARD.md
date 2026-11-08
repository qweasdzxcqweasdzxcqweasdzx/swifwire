# Protocol card (one page)

Copy this block into issue templates / agent prompts.

```
NAME: SwifWire
ROLE: Custom tunnel for SwifTun (Mask || Session)
NOT: VLESS, VMess, Trojan, WireGuard, OpenVPN, Reality-as-core

UNDERLAY (mask):
  - tls13_stable  (DEFAULT, TCP TLS cover)
  - quic_stable    (QUIC/quinn; lab opt-in SWIF_ALLOW_QUIC_STABLE)
  - quic_lab       (alias quic_fast; thin UDP lab cover)
  - null_tcp       (LAB ONLY, needs SWIF_ALLOW_NULL=1)

SESSION:
  - Handshake: SwifHS v0 (X25519 + SHA-256 proofs) — NOT Noise_IK/snow
  - AEAD: ChaCha20-Poly1305
  - Multiplex: stream frames + datagram map
  - Tickets: resume_fast / resume_fs; replay window
  - REKEY: ack under current keys, then advance

CLIENT SURFACE:
  - Local SOCKS5 (product path)
  - C ABI: include/swifwire.h → swifwire.dll (ABI v1)
  - Config: schema/core-config.v1.json
  - URI: swif://host:port?pub=HEX64&mask=…&sni=…

SERVER SURFACE:
  - Binary: swif-edge (sidecar, not Xray plugin)
  - Panel inbound: schema/inbound.v1.json protocol=swifwire
  - Prod: --tls-cert/--tls-key/--cover required (no SWIF_LAB)

KEYS:
  - server.key = 32 bytes SECRET (server only)
  - server.pub = 64 hex PUBLIC (clients / URI)

DOCS:
  - llms.txt, AGENTS.md, docs/INDEX.md, docs/CRYPTO.md
  - docs/CLIENT_SDK.md, docs/SERVER_OPS.md, docs/WIRE.md, docs/HARDENING.md
```
