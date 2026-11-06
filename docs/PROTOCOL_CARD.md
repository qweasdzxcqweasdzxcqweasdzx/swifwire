# Protocol card (one page)

Copy this block into issue templates / agent prompts.

```
NAME: SwifWire
ROLE: Custom tunnel for SwifTun (Mask || Session)
NOT: VLESS, VMess, Trojan, WireGuard, OpenVPN, Reality-as-core

UNDERLAY (mask):
  - tls13_stable  (DEFAULT, TCP TLS cover)
  - quic_fast      (UDP QUIC-like cover)
  - null_tcp       (LAB ONLY, needs SWIF_ALLOW_NULL=1)

SESSION:
  - Handshake: Noise_IK-like, X25519
  - AEAD: ChaCha20-Poly1305
  - Multiplex: stream frames + datagram map
  - Tickets: resume path <2s (lab)

CLIENT SURFACE:
  - Local SOCKS5 (product path)
  - C ABI: include/swifwire.h → swifwire.dll
  - Config: schema/core-config.v1.json
  - URI: swif://host:port?pub=HEX64&mask=…&sni=…

SERVER SURFACE:
  - Binary: swif-edge
  - Panel inbound: schema/inbound.v1.json protocol=swifwire
  - Sidecar pattern (like 3x-ui MTProto)
  - Share: swif_panel_share_uri_alloc / Go ShareURI

KEYS:
  - server.key = 32 bytes SECRET (server only)
  - server.pub = 64 hex PUBLIC (clients / URI)

DOCS:
  - llms.txt, AGENTS.md, docs/INDEX.md
  - docs/CLIENT_SDK.md, docs/SERVER_OPS.md, docs/WIRE.md
```
