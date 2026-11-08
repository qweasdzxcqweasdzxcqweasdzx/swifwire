# SwifWire — план соло-разработки (агент)

**Владелец исполнения:** Cursor agent (вся разработка здесь).  
**Спека:** [DESIGN.md](DESIGN.md), [WIRE.md](WIRE.md).  
**Критерий «готово»:** тег `v0.1.0-mvp` = все галочки §Definition of Done.

**Прогресс (2026-11-06):** **Lab MVP `0.1.0-mvp`.** Все smoke (socks/tls/udp/tun) + `fetch-wintun.ps1` → `third_party/wintun/wintun.dll`. Git-тег — после `git init`/remote (сейчас репо без `.git`). Live OS adapter: admin + `--features os-tun --tun`.

---

## Роль и границы

- Код только в `swifwire/` (ядро, edge, CLI, packs, CI).
- **Не** конечное «обернуть Xray». Legacy — optional later, не блокер MVP.
- Store-ready красивый iOS/Android UI — **после** MVP (на M2–M3 достаточно lib + smoke).
- Инструменты (Rust, etc.) агент ставит сам по мере надобности.

## Locked defaults (не переспрашивать)

| Тема | Решение |
|------|---------|
| Язык | Rust workspace |
| Crypto | X25519 + HKDF-SHA256 + ChaCha20-Poly1305 |
| Handshake | SwifHS v0 1-RTT (not Noise_IK/`snow`); 0-RTT data запрещён |
| Маски MVP | `tls13_stable` + `quic_stable` (lab) / `quic_lab` |
| Padding | всегда ON |
| Probe fail | cover mirror |
| Pack sign | ed25519 |
| UI на MVP | CLI + минимальный Windows shell; mobile = UniFFI |

## Структура

```
swifwire/
  crates/
    swif-wire/ swif-crypto/ swif-shape/ swif-mask/
    swif-session/ swif-mux/ swif-core/
    swif-edge/ swif-cli/
  packs/ tests/ .github/workflows/
```

## Definition of Done — MVP

- [ ] Свой handshake + mux + TCP tunnel + UDP mapping
- [ ] ≥2 mask profiles, переключение с сервера
- [ ] Anti-probe lab: invalid probe ≈ cover baseline
- [ ] Padding API default ON
- [ ] Mask pack update без переустановки бинарника
- [ ] Throughput ≥70% raw TCP в лабе
- [ ] Reconnect (sim wifi↔lte) &lt; 2s по ticket
- [ ] `cargo test` + interop script зелёные

---

## Календарь

| Фаза | Срок | Результат |
|------|------|-----------|
| **0 Setup** | дни 1–2 | workspace + CI |
| **M1 Skeleton** | дни 3–30 | SOCKS через SwifWire (null mask) |
| **M2 Masks** | дни 31–60 | 2 маски, mirror, pack hot-load, resume |
| **M3 MVP** | дни 61–90 | TUN/UDP, perf, tag `v0.1.0-mvp` |

**Ориентир готово: ~90 дней** непрерывной работы агента по вехам.

---

## Фаза 0 — Setup (дни 1–2)

1. Rust stable toolchain.
2. Cargo workspace + stub crates.
3. CI: fmt + clippy + test.
4. Stub test vectors из WIRE.md.

**Exit:** `cargo test -p swif-wire` (framing).

## Фаза 1 — M1 (дни 3–30)

1. `swif-wire` — varint/frames + fuzz.
2. `swif-crypto` — AEAD, HKDF, SwifHS helpers (not `snow`).
3. `swif-session` — records, rekey, ticket.
4. `swif-mux` — STREAM_* + DATAGRAM + window.
5. `swif-shape` — histogram pad.
6. Mask `null_tcp` (только lab).
7. `swif-edge` + `swif-cli` SOCKS5.
8. Interop localhost + throughput script.

**Exit M1:** SOCKS↔edge работает; padding on; CI green.

## Фаза 2 — M2 (дни 31–60)

1. `tls13_stable` mask + templates из pack.
2. Cover mirror (lab: local caddy/nginx).
3. `quic_fast` (thin UDP cover; не идеальный Chrome).
4. Pack load + ed25519 + `MASK_OFFER/ACK`.
5. Ticket resume harness &lt;2s.
6. UniFFI smoke API.
7. Shape + probe CI gates.

**Exit M2:** 2 masks; hot pack; probe gate; resume OK.

## Фаза 3 — M3 (дни 61–90)

1. TUN (Win/mac/linux) + UDP mapping E2E.
2. Dial policy + HEALTH/BACKOFF.
3. Perf ≥70%; reconnect suite.
4. Минимальный Windows tray shell + edge runbook.
5. Tag `v0.1.0-mvp`.

**Exit M3 = продукт «готово» по DoD.**

## После MVP (отдельный запрос)

Полировка mobile UI, `swif://` sub, prod CDN cover, выпил любого legacy.

---

## Правила работы агента

1. Одна веха/crate → зелёный `cargo test` → следующая.
2. Секреты не в git; только `gen-keys` lab.
3. Отчёты пользователю на границах M0/M1/M2/M3 или реальном блокере.
4. Блокер один раз: prod cover-домен — до freeze M2; до этого localhost cover.

## Первый шаг после «ок, делай»

Фаза 0: workspace + `swif-wire` framing по WIRE.md.
