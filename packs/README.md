# Mask packs

| File | Role |
|------|------|
| `example-pack.dev.json` | Unsigned template (edit → re-sign) |
| `prod-baseline.v1.json` | Signed baseline for 0.3.0 clients |
| `pack.pub` | Trust verifying key (hex) — ship to clients |
| `pack.key` | **Ops only** (gitignored) — never distribute |

```powershell
cargo run -p swif-mask --bin swif-pack -- gen-key --key packs/pack.key --pub-out packs/pack.pub
cargo run -p swif-mask --bin swif-pack -- sign --input packs/example-pack.dev.json --key packs/pack.key --output packs/prod-baseline.v1.json
cargo run -p swif-mask --bin swif-pack -- verify --pack packs/prod-baseline.v1.json --trust packs/pack.pub
```
