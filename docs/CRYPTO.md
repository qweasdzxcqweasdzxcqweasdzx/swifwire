# SwifWire cryptography notes (SwifHS v0)

## Threat model (short)

- **On-path censor / DPI:** sees only the **mask** (TLS/QUIC cover). Must not see `SWI1` / SwifHS on bare TCP/UDP.
- **Active probe without server pub:** edge continues cover (HTTP mirror / builtin lab). No ServerHelloInner.
- **Active probe with wrong static key:** same cover path (proof fail).
- **Ticket replay:** server `TicketReplayWindow` rejects duplicate resume tickets.
- **Not claimed:** anonymity against global passive adversary; “unblockable” middleboxes; Reality compatibility.

## What SwifHS is (and is not)

| | |
|--|--|
| **Is** | Custom 1-RTT static-DH handshake: X25519 + SHA-256 labeled proofs + HKDF session keys |
| **Is not** | Noise_IK, `snow`, Noise protocol names, or wire-compatible with Noise frameworks |

Wire name: **SwifHS v0** (`PROTOCOL_VERSION = 0`). Migrating to real Noise_IK requires version bump + new profile.

## Session AEAD

- Cipher: ChaCha20-Poly1305
- Nonce: 96-bit = `key_salt (4 BE)` ‖ `packet_counter (8 BE)`
- AAD: record `hdr` ‖ length varint
- Counter per direction; reuse = protocol violation
- REKEY: ack under **current** keys, then both `advance_rekey` (WIRE §4.5)

## Tickets

- Seal with **ticket master** (32 bytes):
  - Lab/compat default: server static **public** bytes
  - Prod: `--ticket-master` file (32 raw) or `SWIF_TICKET_MASTER_HEX` — **separate** from static pub
- TTL: 24h (`TICKET_TTL_SECS`)
- `resume_fast`: eph=0, PSK only
- `resume_fs`: fresh eph mixed with PSK
- Replay digest window on resume path

## Vectors

Canonical hex fixtures: `tests/vectors/`. Loaded by `swif-session` / `swif-crypto` tests.

## Mask crypto (out of session scope)

TLS/QUIC cover keys and certificates are **ops assets** (PEM / pack). Session layer must not depend on specific JA3.
