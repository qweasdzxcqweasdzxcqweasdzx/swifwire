# Mobile FFI skeleton (0.4.0)

Product path remains SOCKS + C ABI. UniFFI is the **planned** Android/iOS surface.

## Planned UniFFI surface (no ABI break of C)

```
namespace swifwire {
  string version();
  u32 abi_version(); // mirrors swif_abi_version == 1
  void start(string config_json) throws CoreError;
  void stop();
  string status_json();
  void apply_mask_pack(bytes pack);
  void import_subscription(string url_or_blob);
  string? legacy_fallback_uri();
}
```

## Reconnect / battery

- Ticket `resume_fs` preferred on mobile when pack flag set.
- Shaper profile `mobile_idle` (idle Ping + min_pad) — already in swif-shape.
- Target: resume &lt;2s on wifi↔cell (lab vector already covers under-2s resume).

## Ship artifacts (0.5+)

- Android: AAR via uniffi + jni
- iOS: XCFramework

0.4.0 ships this doc + `ffi/swifwire.udl` skeleton + C ABI parity. AAR/XCFramework generation lands in 0.5 CI.
