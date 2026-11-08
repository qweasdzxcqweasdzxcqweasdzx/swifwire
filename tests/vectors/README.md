# SwifWire cryptographic test vectors (v0)

Deterministic fixtures for SwifHS / AEAD. Do **not** put real server keys here.

| File | Contents |
|------|----------|
| `aead_record_v0.hex` | seal_record(key=0x11×32, salt=01020304, ctr=0, pt=`hello-frame`) |
| `kdf_session_v0.json` | derive_session_keys(shared, transcript) both 32 ASCII bytes |
| `handshake_wrong_key.md` | Behavioral: wrong static → Err (cover path) |

Regenerate AEAD/KDF via:

```powershell
cargo run -q -p swif-crypto --example gen_vectors
```
