# SwifWire v0 — Wire Format (Normative)

**Version:** 0.0  
**Endianness:** network byte order (big-endian) unless noted  
**Varint:** unsigned LEB128, max 5 bytes for u32, 10 for u64  

## 0. Scope split

| Layer | Normative here? |
|-------|-----------------|
| Session AEAD records + mux/control/datagram frames | **YES** |
| Mask on-wire (TLS/QUIC templates) | **NO** — only in mask pack |
| Cover origin HTTP | **NO** |

После установки session keys все SwifWire сообщения — AEAD records. До keys — только Noise messages внутри mask pipe (байты маски не специфицированы здесь).

---

## 1. AEAD record (post-handshake)

```
+--------+--------+----------------+----------+
| hdr    | len    | ciphertext     | tag      |
| 1 byte | varint | len bytes      | 16 bytes |
+--------+--------+----------------+----------+
```

### 1.1 hdr (1 byte)

```
bit 7..4  version_nibble   // v0 = 0
bit 3..0  flags
          0x1 = HAS_PAD_HINT (debug/lab only; prod packs set 0)
          0x2 = KEY_PHASE    // toggles on rekey
          other bits MBZ
```

### 1.2 length

Varint = length of ciphertext **excluding** tag.  
Plaintext length = ciphertext length (ChaCha20-Poly1305).

### 1.3 Nonce / seq

- 96-bit nonce = `key_salt (4 bytes BE)` ‖ `packet_counter (8 bytes BE)`
- `key_salt` from HKDF expand label `swifwire/v0/nonce_salt` (per direction)
- `packet_counter` starts at 0, increments by 1 per record per direction
- Reuse of (key, nonce) = protocol violation → hard close

### 1.4 AEAD

- Algorithm: ChaCha20-Poly1305 (RFC 8439)
- AAD = `hdr || len_varint_bytes` (exact bytes on wire)
- Tag: 16 bytes appended

### 1.5 Plaintext layout after decrypt

```
+-----------+---------------------------+
| frame+    | optional padding opaque   |
+-----------+---------------------------+
```

Padding: zero or more random bytes; **not authenticated as structure** — only as AEAD blob. Receiver strips using frame parser (frames self-delimited); remaining = pad.  
Shaper chooses pad length; content MUST be indistinguishable from random (CSPRNG).

---

## 2. Frame types

Frames are concatenated inside plaintext (usually 1 frame + pad).  
Each frame:

```
type:u8 | flags:u8 | body_len:varint | body
```

| type | name | body |
|------|------|------|
| 0x01 | STREAM_OPEN | `stream_id:u32 \| initial_window:u32 \| meta_len:varint \| meta` |
| 0x02 | STREAM_DATA | `stream_id:u32 \| data` |
| 0x03 | STREAM_RESET | `stream_id:u32 \| error:u16` |
| 0x04 | STREAM_WINDOW | `stream_id:u32 \| credit:u32` |
| 0x10 | DATAGRAM | `assoc_id:u32 \| data` |
| 0x11 | DATAGRAM_CLOSE | `assoc_id:u32 \| error:u16` |
| 0x20 | CONTROL | `ctrl_type:u16 \| payload` |
| 0x2F | PING | `opaque 0..32` |
| 0x30 | PONG | `echo opaque` |
| 0x7F | PADDING_ONLY | empty body (entire record may be pad) |

`meta` for STREAM_OPEN (MVP): UTF-8 host hint optional; or binary `addr_type|addr|port` for VPN (see §5).

Unknown `type`: if flag bit0 of frame.flags = CRITICAL → close session; else skip.

---

## 3. CONTROL payload

`ctrl_type` values:

| u16 | name | payload |
|-----|------|---------|
| 1 | CAPS | `caps_bitset:u64 \| packs_hash: [u8;32] optional if flag` |
| 2 | MASK_OFFER | `profile_id:varstr \| pack_hash:[u8;32] \| urgency:u8` |
| 3 | MASK_ACK | `profile_id:varstr \| status:u8` (0=applied,1=deferred,2=reject) |
| 4 | HEALTH | `rtt_ms:u32 \| loss_x1000:u16` |
| 5 | BACKOFF | `delay_ms:u32 \| code:u16` |
| 6 | REKEY | empty |
| 7 | CLOSE | `code:u16 \| reason:varstr` |
| 8 | TICKET | `ticket:varbytes` |

`varstr` = `varint_len || utf8`  
`varbytes` = `varint_len || bytes`

### 3.1 Caps bits (u64)

```
bit0  datagram
bit1  ticket_resume
bit2  mask_quic_fast
bit3  early_control
bit4  addr_v6
bit5  fake_dns
…
```

---

## 4. Handshake messages (inside mask pipe, pre-AEAD) — **SwifHS v0**

Не AEAD-record. Это **не** Noise_IK / `snow`. Имя протокола: **SwifHS v0** (`PROTOCOL_VERSION = 0`).  
Миграция на настоящий Noise_IK = bump `version` + новый профиль.

Логический plaintext внутри mask application data:

### 4.1 ClientHelloInner (encode)

```
magic_inner:  [u8;4] = 0x53 0x57 0x49 0x31   // "SWI1" — ONLY inside mask
version:      u16 BE = 0
eph_pub:      [u8;32]
static_proof: [u8;32]   // SHA256(shared || label) — see below
caps:         u64 BE
ticket_len:   u16 BE
ticket:       bytes
pad_len:      u16 BE
pad:          random
```

### 4.2 ServerHelloInner (encode)

```
version:      u16 BE
eph_pub:      [u8;32]
static_proof: [u8;32]
caps:         u64 BE
ticket_len:   u16 BE
ticket:       bytes
pad_len:      u16 BE
pad:          random
```

### 4.3 SwifHS v0 key schedule (full HS)

1. Client eph × server static → `es`; client proof = `SHA256(es || "client-es")`
2. Server eph × client eph → `ee`; server proof = `SHA256(ee || "server-ee")`
3. `shared = es || ee` (64 bytes)
4. `transcript = SHA256(client_raw || server_raw)`
5. Session keys = existing `derive_session_keys(shared, transcript)` (HKDF in swif-crypto)
6. Resume PSK = `SHA256(shared || "ticket-secret")` sealed into ticket

### 4.4 Resume modes

| Mode | Client `eph_pub` | Proof labels | FS |
|------|------------------|--------------|----|
| `resume_fast` (default) | 32× `0x00` | `client-resume` / `server-resume` | no |
| `resume_fs` | fresh eph | `client-resume-fs` / `server-resume-fs`; keys from `psk \|\| ee` | yes |

**Важно:** `magic_inner` только внутри mask. Probe без ключа маски magic не видит.

Если SwifHS fail: сервер **не** отвечает ServerHelloInner; продолжает cover (`mirror_upstream` или lab `builtin_http`).

---

## 5. STREAM_OPEN meta (VPN MVP)

```
ver:u8 = 1
cmd:u8 = 1 (CONNECT TCP) | 2 (UDP_ASSOC)
atype:u8 = 1(IPv4) | 3(domain) | 4(IPv6)
addr:  4 | varstr | 16
port:  u16
```

---

## 6. Examples

### 6.1 Field table — STREAM_DATA frame (plaintext before pad)

| Offset | Size | Value | Meaning |
|--------|------|-------|---------|
| 0 | 1 | `02` | STREAM_DATA |
| 1 | 1 | `00` | flags |
| 2 | 1+ | `05` | body_len=5 (example) |
| … | 4 | `00 00 01 2C` | stream_id=300 |
| … | 1 | `41` | data `"A"` |

### 6.2 Hex sketch — AEAD record wrapping one PING (illustrative, fake key)

Assume plaintext frame = `2f 00 00` (PING, flags0, body_len0) + 5 bytes pad.

```
hdr:        00
len:        13          # varint 19 = 3+5+? wait: ciphertext len = plaintext len = 8
ciphertext: <8 bytes>
tag:        <16 bytes>
```

*(Лабораторные fixtures с test vectors — в `swifwire/tests/vectors/` после появления кода.)*

### 6.3 What we intentionally do NOT fix

- TLS ClientHello cipher suites / extension order  
- QUIC version / DCID length  
- TCP MSS / TLS record max size of mask  
- Cover HTTP status body  
- Port numbers  

These live in **mask pack** only.

---

## 7. Error codes (u16)

| code | meaning |
|------|---------|
| 0 | OK / normal close |
| 1 | protocol |
| 2 | auth |
| 3 | policy / backoff |
| 4 | stream reset peer |
| 5 | unsupported cap |
| 6 | internal |

---

## 8. Versioning

- `hdr` version_nibble or handshake `version` mismatch → server cover path or CONTROL_CLOSE.
- New frame types: additive; CRITICAL flag for breaking.

---

*Normative companion to DESIGN.md §C*
