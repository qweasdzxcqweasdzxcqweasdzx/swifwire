# UniFFI build stub (0.5)

UDL: [`ffi/swifwire.udl`](../ffi/swifwire.udl)

## Planned commands (CI later)

```bash
# requires uniffi-bindgen + NDK / Xcode
cargo build -p swif-ffi --features uniffi
uniffi-bindgen generate ffi/swifwire.udl --language kotlin --out-dir dist/android/
uniffi-bindgen generate ffi/swifwire.udl --language swift --out-dir dist/ios/
```

0.5.0-wip does **not** ship AAR/XCFramework yet — C ABI remains the product host surface.
