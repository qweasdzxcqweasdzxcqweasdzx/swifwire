# JA4 / JA3 corpus (craft encoder)

Golden digests for **pack-driven** ClientHello (`swif-pack ja3`), not a live browser capture dump.

## Workflow when DPI says “not Chrome”

1. Capture real browser ClientHello (Wireshark / JA4 tool).
2. `swif-pack ja3 --pack packs/….json --sni YOUR_SNI`
3. Diff `ja4_a` / extension order vs capture.
4. Fix **pack** (`client_hello_profile`, ALPN, GREASE, suites) — do not hardcode a one-off CH in rustls.

## Live vs lab encoder

| Path | Notes |
|------|--------|
| Lab `build_client_hello_record` | Full intended extension list (may include ECH/ALPS stubs) |
| Live `dial_tls_craft` | `omit_experimental=true` (skips 0x001b / 0x4469 / 0xfe0d) for rustls interop |

Regenerate goldens:

```powershell
cargo run -q -p swif-mask --bin swif-pack -- ja3 --pack packs/example-pack.dev.json --sni cdn.example.com
```
