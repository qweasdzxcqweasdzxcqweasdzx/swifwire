# SwifWire v0 — Internal Design Doc

**Product:** SwifTun  
**Audience:** founders + core eng  
**Status:** Approved defaults for MVP kickoff (см. §H для открытых решений)  
**Date:** 2026-11-05

---

## A. Executive summary

1. **Проблема:** прод на чужих клиентах (Happ) и чужих сигнатурах (VLESS/Reality/WS/HY2) → медленная смена облика, общий fingerprint экосистемы.
2. **Решение:** своё ядро **SwifCore** + wire **SwifWire v0** с жёстким разделением **Mask ∥ Session**. Маска — сменный «облик» (TLS-like / QUIC-like); сессия — наш AEAD + mux + datagram.
3. **Default runtime:** **Rust** (один код → FFI на mobile/desktop). UI нативный; ядро — library + tun worker.
4. **Crypto default:** X25519 + HKDF-SHA256 + ChaCha20-Poly1305 (AES-GCM как optional HW path). Handshake внутри маски: **Noise_IK**-подобный 1-RTT с ticket resume; 0-RTT только для replay-safe idempotent control, не для туннеля данных на MVP.
5. **Anti-probe:** невалидный handshake → **transparent mirror** на реальный cover origin (своя схема, не fork Reality constants). Сканер видит cover; клиент с ключом — session.
6. **Agility:** mask packs + feature flags доставляются с control plane, подпись ed25519, hot-apply без store release.
7. **Padding/shaping — first-class API** в каждом send path; профили задают length + timing policy.
8. **Migration:** dual-stack ноды: SwifWire + legacy inbound; клиент v1 говорит оба; v2 — только SwifWire.
9. **Не обещаем:** неуязвимость к ТСПУ/GFW. Обещаем: смена маски/флагов за часы, измеримый probe-resistance lab suite.
10. **MVP exit:** TCP tunnel + UDP map + ≥2 masks + server-driven switch + padding on + reconnect &lt;2s wifi↔lte + ≥70% raw TCP throughput в лабе.
11. **Tradeoff принят:** чуть выше CPU на shaping/padding ради DPI agility; latency handshake ~TLS1.3-like, не «голый Noise поверх TCP».
12. **Non-goal MVP:** полный browser fingerprint spoof, WebRTC stack, obfuscation «на уровне приложения» вне mask.
13. **Control plane:** silent capability bits в handshake; mask switch / health / backoff — control frames внутри сессии + отдельный HTTPS bootstrap для pack URL.
14. **Mobile:** sleep-aware keepalive, cheap reconnect via ticket, no busy poll; battery budget в shaping profile.

---

## B. Threat model

### B.1 Adversary classes

| Класс | Возможности | Не возможности (для модели) |
|-------|-------------|------------------------------|
| **Passive DPI** (ТСПУ/GFW mirror) | L3–L7 header/SNI/ALPN/QUIC type, length seq, timing histograms, JA3/JA4-like, flow duration | Ломает AEAD без ключа |
| **Active probe** | Синтетические ClientHello / QUIC Initial / replay; ожидает отличимый ответ | Не имеет share secret клиента |
| **IP/ASN intel** | Блок/throttle по IP/ASN/geo, short TTL lists | Не читает payload |
| **Endpoint compromise** | Украден node key / pack signing key | Вне протокола; ops incident |

### B.2 Что жжёт чужие/типовые стеки (сигнатуры)

1. **Handshake fixed bytes** — известные magic / version / UUID layout (VLESS-like).
2. **TLS ClientHello template** — одинаковый JA3/JA4 у всех пользователей одного клиента.
3. **ALPN / extension order** — несовпадение с заявленным cover (Chrome vs «TLS»).
4. **QUIC** — нестандартные packet number / grease / CRYPTO frame timing.
5. **Length oracle** — узкий набор размеров записей (mux frame без padding).
6. **Timing** — bursty request-response без idle/padding (особенно HTTP/2-like mux).
7. **Multiplex pattern** — фиксированный stream id allocation, ping period.
8. **App fingerprint** — User-Agent Happ, SNI-списки, destination fan-out.
9. **UDP/TCP ratio** — HY2-like всегда UDP на одних портах.
10. **Post-handshake** — first app packet length/time after Finished слишком стабилен.

### B.3 Что протокол обязан закрывать

| Угроза | Механизм SwifWire |
|--------|-------------------|
| Passive magic / UUID wire | Нет plaintext identity до AEAD; auth внутри Noise после mask |
| Отличимый fail на probe | Mirror-to-cover; одинаковый path до auth success |
| Стабильные length | Mandatory pad API + mask-driven distribution |
| Статичный TLS/QUIC отпечаток | Сменные mask packs (не hardcoded ClientHello) |
| Долгий один session key | Rekey; ticket bound to epoch |
| Replay 0-RTT data | MVP: 0-RTT только control; data после 1-RTT confirm |
| Mux fingerprint | Randomized stream IDs; shaped control cadence |

### B.4 Что остаётся operational (не «протокол сам»)

- **IP diversity** (ротация edge, anycast осторожно — GFW любит anycast heuristics).
- **Domain / SNI strategy** (cover domains, short TTL DNS, не один SNI на ASN).
- **Port / transport mix** (443/tcp, 443/udp, редкие 80 — по политике).
- **Rate limits / capacity** при throttle.
- **Client distribution** (свой клиент ≠ Happ store fingerprint).
- **Key hygiene** (node keys, pack signing, rotation).

### B.5 Mobile-specific threats

- NAT rebinding → ticket reconnect, не полный handshake каждый раз.
- Sleep → no aggressive keepalive; profile `mobile_idle`.
- Network switch wifi↔lte → migrate session &lt;2s (см. accept criteria).

---

## C. Protocol spec SwifWire v0 (нормативная)

Нормативный бинарный формат — [WIRE.md](WIRE.md). Здесь — архитектура и политика.

### C.1 Goals

- Собственный session/mux/datagram поверх **сменной** маски.
- Forward secrecy (эфемерный X25519).
- Anti-probe: fail-closed к cover traffic.
- Hot-update masks + feature flags.
- TCP tunnel + UDP mapping для VPN use-case.
- Работа за CGNAT, смена IP, sleep.

### C.2 Non-goals (v0)

- Совместимость wire с VLESS/Reality/HY2 (только dual-stack на ноде).
- «Стать неотличимым от Chrome навсегда».
- Post-quantum на MVP (закладываем version bit).
- Multi-hop onion / mixnet.
- Browser-in-the-middle (реальный TLS к origin для клиента).

### C.3 Layering

```
┌─────────────────────────────────────────────┐
│  App / TUN / DNS / Route (SwifCore upper)    │
├─────────────────────────────────────────────┤
│  Control  │  Stream mux  │  Datagram map    │
├─────────────────────────────────────────────┤
│  Session (AEAD records, rekey, tickets)     │
├─────────────────────────────────────────────┤
│  Handshake / Auth (Noise_IK-like)           │
├─────────────────────────────────────────────┤
│  Mask profile (TLS-like | QUIC-like | …)    │  ← hot-swappable pack
├─────────────────────────────────────────────┤
│  UDP / TCP underlay                         │
└─────────────────────────────────────────────┘
```

**Invariant:** всё, что ниже Session, **не** содержит SwifWire magic в plaintext. Маска полностью владеет on-wire байтами до «открытия» канала для Session.

### C.4 Handshake (default)

**Choice: Noise_IK style over established mask channel (1-RTT).**

Почему IK, не XX: клиент знает static key сервера (из подписки/нод-листа) → меньше round-trips на mobile.  
Почему не «чистый TLS1.3»: маска уже может быть TLS-like; второй настоящий TLS избыточен и даёт двойной fingerprint. Inner — компактный Noise.

**Flow (logical):**

1. Mask dial → bi-directional reliable byte/datagram pipe (profile-defined).
2. Client → Server: `ClientHelloInner` = eph_pub || noise_msg || client_caps || pad  
   AEAD ещё нет; integrity = Noise transcript.
3. Server: если Noise fail / caps unknown → **не рвём маску**; уходим в cover mirror path (см. §C.8 / §D probe). Если OK → `ServerHelloInner` = eph_pub || noise_msg || server_caps || ticket_offer || pad.
4. Derive: `CK, TK` via HKDF labels `swifwire/v0/key`, `swifwire/v0/ticket`.
5. First data frame only after keys installed (1-RTT).

**0-RTT policy (MVP):** ticket may carry early secret for **CONTROL_EARLY** only (health, mask preference). **No TUN payload in 0-RTT.** Replay window: server-side bloom + ticket age ≤ 24h.

**Forward secrecy:** ephemeral X25519 each full handshake; ticket does not extend FS beyond ticket lifetime.

### C.5 Session keys, rekey, ticket

| Item | Default |
|------|---------|
| AEAD | ChaCha20-Poly1305; nonce = 96-bit (`salt_32 || packet_counter_64`) |
| Directions | separate keys `k_c2s`, `k_s2c` |
| Counter | monotonic per direction; overflow → rekey |
| Rekey | after 2^32 frames **or** 1h **or** CONTROL_REKEY |
| Ticket | opaque 16–64B, sealed with server rotating key; binds node_id + epoch + client_id_hash |
| Resume | 1-RTT shortened (PSK from ticket + fresh eph) |

KDF (схема, без секретов):

```
PRK = HKDF-Extract(salt=transcript_hash, ikm=Noise_shared)
k_c2s || k_s2c || k_ticket || k_padseed =
  HKDF-Expand(PRK, info="swifwire/v0/"+label, L=…)
```

### C.6 Stream mux + datagram

- **STREAM_OPEN / STREAM_DATA / STREAM_RESET / STREAM_WINDOW** — TCP-like tunnels (SOCKS/VPN TCP).
- Stream ID: random odd (client) / even (server), 32-bit; avoid sequential 1,3,5 fingerprint.
- Flow control: simple credit window (initial 256 KiB); not full H2 priority tree (reduces fingerprint + complexity).
- **DATAGRAM** frames: UDP association id + payload; idle timeout 60s default.
- **Mapping:** TUN IPv4/IPv6 → stream (TCP) or datagram (UDP); ICMP echo optional later.

### C.7 Padding & traffic shaping API (mandatory)

Каждый egress path вызывает:

```text
Shaper.wrap(plain_record) -> shaped_bytes
Shaper.on_idle(now) -> optional_cover_frame
Shaper.profile_id -> u32
```

Profiles задают:

- length distribution (histogram or piecewise);
- max pad per record;
- inter-departure delay (optional jitter);
- idle cover cadence (mobile vs desktop).

**Default ON.** Disable только lab build flag `SWIF_SHAPE=off`.

### C.8 Mask profiles

| Profile ID (MVP) | Underlay | Role |
|------------------|----------|------|
| `tls13_stable` | TCP/443 | Default desktop/mobile; ClientHello templates from pack |
| `quic_fast` | UDP/443 | Throughput / lossy mobile; QUIC-like Initial+1RTT cover |

**Pack format:** signed JSON/CBOR — templates, grease policy, ALPN sets, SNI pool refs, shaper binding, min client version. См. `schema/mask-pack.v1.json`.

**Delivery:** HTTPS bootstrap URL in subscription → download pack → verify ed25519 → store → `CONTROL_MASK_SWITCH` or next dial.

**Что НЕ фиксируем в wire session layer:** ClientHello bytes, QUIC header form, record sizes of mask — только pack.

### C.9 Control plane

| Message | Direction | Use |
|---------|-----------|-----|
| `CAPS` | both | feature bits (quic_fast, early_ctrl, rekey_v2…) |
| `MASK_OFFER` | S→C | recommended profile id + pack hash |
| `MASK_ACK` | C→S | applied / deferred |
| `HEALTH` | both | RTT sample, loss hint |
| `BACKOFF` | S→C | ms + reason code (throttle) |
| `REKEY` | both | force |
| `CLOSE` | both | graceful |

Silent negotiation: unknown caps → ignore bit; required bit missing → try next mask/node.

### C.10 Failure modes & fallback

```
dial mask A → handshake fail (auth) → treat as cover OK for probe;
             (for real client) → soft-fail → mask B → node2 → legacy bridge (phase1 only)
network change → ticket resume on same node → else full handshake
throttle BACKOFF → reduce rate / switch mask / switch node
```

**Client policy default:** prefer `tls13_stable`; if 3 consecutive handshake timeouts → `quic_fast`; if both fail → legacy outbound (phase 1).

---

## D. Core architecture

### D.1 Runtime recommendation

**Default: Rust library `swif_core`.**

| Почему Rust | Почему не Go / C++ / Kotlin-first |
|-------------|----------------------------------|
| Один код на iOS/Android (UniFFI/FFI) + desktop | Go: GC + mobile embed pain |
| Нет data races в mux/shaper | C++: audit cost |
| Crypto crates (ring/aws-lc/rustls patterns) | Kotlin: нет desktop/mac parity |

UI: Swift/Kotlin/SwiftUI/WinUI — тонкие; **не** дублировать crypto.

### D.2 Modules

```
swif_core/
  mask/          # profile drivers: tls13_stable, quic_fast
  crypto/        # noise, aead, kdf, ticket
  session/       # record layer, rekey
  mux/           # streams + datagrams
  shape/         # padding API
  tun/           # platform TUN glue (via FFI callbacks)
  dns/           # fake-ip / doh optional
  route/         # split tunnel rules
  control/       # frames + pack apply
  legacy/        # phase1: outbound adapters only (not identity)
  probe_mirror/  # server-side cover relay
```

### D.3 UI ↔ Core API (stable C ABI / UniFFI)

```text
core_start(config_json) -> handle
core_stop(handle)
core_set_route_mode(handle, mode)
core_import_subscription(handle, url_or_blob)
core_apply_mask_pack(handle, bytes) -> Result
core_status(handle) -> json  # mask, rtt, bytes, state
core_on_event(callback)      # need_login, backoff, mask_switched, error
```

Config JSON: nodes, keys refs, feature flags, shaper override.

### D.4 Hot-update mask pack / flags

1. Control `MASK_OFFER` or bootstrap poll (ETag).
2. Download blob; verify signature + min_version.
3. Stage pack; next dial uses it **or** mid-session switch only at idle (MVP: next dial).
4. Feature flags: bitfield in CAPS + remote JSON `flags` (kill switch for quic_fast etc.).

### D.5 Server probe behavior (своя схема, не Reality copy)

**Идея:** до успешного inner auth весь underlay трафик — валидный cover к **cover origin** (реальный TLS/HTTP сервер, которым мы управляем или партнёрский).

- Невалидный / чужой ClientHelloInner → **не** TCP RST с отличимым timing; продолжаем cover response как обычный origin.
- Успешный auth → hijack: дальнейшие bytes — SwifWire session (mask may continue record framing).
- Active probe без ключа статистически видит cover.  
- **Не фиксируем** чужие fingerprint constants; cover certs/templates — наши ops assets в pack/node config.

---

## E. Migration plan (VLESS / Reality / HY2 → SwifWire)

### Phase 0 (now)

- Design freeze (этот doc).
- Pack schema + two dummy packs.
- Lab harness skeletons.

### Phase 1 — Dual-stack (compat)

| Component | Behavior |
|-----------|----------|
| Edge | Listeners: SwifWire + legacy ( torz/xray or thin rust legacy ) on same IP different paths/ports OR SNI-routed |
| Client SwifTun | Core: SwifWire primary; legacy outbound plugin for old nodes |
| Subscription | Nodes tagged `swifwire` / `legacy` |
| Studio/proxy | Может временно оставаться на legacy до SwifWire client |

### Phase 2 — SwifWire only

- New nodes: SwifWire only.
- Client removes legacy (feature flag then delete).
- Old Happ users: bridge gateway period (optional) then sunset.

### Dual-stack node sketch

```
:443 tcp ─ mask terminate ─ auth? ─ yes → swifwire session
                              └─ no  → cover origin
:443 udp ─ quic_fast mask ─ same
:8443    ─ legacy VLESS (phase1 only, sunset date)
```

---

## F. Test plan

### F.1 Unit

- AEAD roundtrip, nonce uniqueness assert, rekey.
- Varint / frame parse fuzz (cargo-fuzz).
- Mux window / reset.
- Ticket seal/open expiry.

### F.2 Interop

- Matrix: Win/macOS/iOS/Android client × Linux edge.
- 1-RTT + ticket resume + network change.

### F.3 Shape tests

- Collect length & inter-arrival histograms vs pack target (KL divergence threshold).
- `SWIF_SHAPE=off` vs on regression gate.

### F.4 Active-probe tests (lab)

- Corpus of invalid handshakes / random probes → response byte-distance to pure cover baseline (same origin without SwifWire) within bound.
- **Не** публикуем как «гарантия против ТСПУ»; это CI gate на регрессии.

### F.5 Perf

- iperf3-like through TUN vs raw TCP same path; accept ≥70%.
- Handshake p50/p95 latency.
- wifi↔lte reconnect p95 &lt; 2s (ticket path).

### F.6 Mobile

- Background 30m; traffic bytes budget.
- NAT timeout simulation.

---

## G. 30 / 60 / 90 day roadmap

### Days 0–30 — Foundations (MVP skeleton)

- [ ] `swif_core` crate: crypto + framing + mux + null mask (raw TCP) 
- [ ] Linux edge binary: accept null-mask SwifWire, TCP tunnel only
- [ ] Desktop CLI client → SOCKS/TUN experimental
- [ ] Padding API wired (even if profile = uniform)
- [ ] Unit + interop CI
- **Milestone M1:** TCP tunnel lab, 1 mask = `null` (dev only)

### Days 31–60 — Masks + anti-probe + mobile FFI

- [ ] `tls13_stable` mask + cover mirror path
- [ ] Second mask `quic_fast` (can be experimental)
- [ ] Ticket resume; reconnect tests
- [ ] Mask pack sign/verify + hot load
- [ ] UniFFI → Android + iOS thin shells (dial/status)
- [ ] Shape histograms gate
- **Milestone M2:** ≥2 masks, probe lab gate green, pack hot-update

### Days 61–90 — Product MVP

- [ ] UDP datagram mapping
- [ ] Server-driven MASK_OFFER / BACKOFF
- [ ] Dual-stack node with legacy
- [ ] Perf ≥70%; reconnect &lt;2s
- [ ] Windows/macOS app shell behind feature flag
- [ ] Dogfood on internal SwifTun staging
- **Milestone M3 = MVP accept criteria**

---

## H. Open questions / decisions needed from founder

1. **Cover origins:** свои домены/CDN или партнёрские? (влияет на ops и legal)
2. **Subscription format:** расширять текущий Happ-compatible URL или новый `swif://` сразу?
3. **China SKU:** отдельный pack channel / node set или один global?
4. **Legacy sunset date** для VLESS/HY2 (нужна дата для dual-stack cost).
5. **App store risk:** mask packs с TLS templates — политика обновления без review (JS-free binary packs OK?).
6. **AES-GCM HW:** обязателен на Apple Silicon или ChaCha everywhere для единообразия?
7. **Studio (авто-видео):** переводить прокси-движок на SwifWire в phase1 или ждать phase2 client?
8. **Budget:** in-house Rust team size (1 vs 2) — режет 90-day scope (quic_fast может уехать за M3).

---

## Defaults locked for eng (unless founder overrides §H)

| Topic | Default |
|-------|---------|
| Core language | Rust |
| Inner HS | Noise_IK-like, 1-RTT |
| AEAD | ChaCha20-Poly1305 |
| 0-RTT data | Forbidden on MVP |
| Masks MVP | tls13_stable + quic_fast |
| Padding | On |
| Probe fail | Cover mirror |
| Legacy | Dual-stack phase1 only |
| Pack sign | ed25519 |
| Resume | Tickets 24h |

---

*End of DESIGN.md — wire bits in WIRE.md*
