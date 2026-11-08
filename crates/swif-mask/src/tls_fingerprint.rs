//! ClientHello fingerprint budget (honest uTLS status).
//!
//! rustls randomizes extension *positions* and does **not** expose fixed browser
//! extension order (no JA3/JA4 clone). Pack profiles still document the intended
//! order for agents / future craftls-class stacks.

use crate::tls_profile::ClientHelloProfile;

/// What SwifWire controls today vs what needs a uTLS-class stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintBudget {
    pub cipher_suites: bool,
    pub kx_groups: bool,
    pub signature_schemes: bool,
    pub alpn: bool,
    /// Fixed browser extension order — **false** on rustls.
    pub extension_order: bool,
}

impl FingerprintBudget {
    pub const RUSTLS_PARTIAL: Self = Self {
        cipher_suites: true,
        kx_groups: true,
        signature_schemes: true,
        alpn: true,
        extension_order: false,
    };
}

/// Intended TLS extension type ids (IANA) for a browser-like ClientHello.
/// Not applied by rustls; consumed by docs / future binders.
pub fn intended_extension_order(profile: ClientHelloProfile) -> &'static [u16] {
    // Common Chrome-ish order (approx): SNI, ESNI/ECH omit, status_request, supported_groups,
    // ec_point_formats, signature_algorithms, ALPN, key_share, supported_versions, …
    match profile {
        ClientHelloProfile::ChromeStable => &[
            0x0000, // server_name
            0x0005, // status_request
            0x000a, // supported_groups
            0x000b, // ec_point_formats
            0x000d, // signature_algorithms
            0x0010, // application_layer_protocol_negotiation
            0x0012, // signed_certificate_timestamp
            0x0017, // extended_master_secret
            0x001b, // compress_certificate
            0x002b, // supported_versions
            0x002d, // psk_key_exchange_modes
            0x0033, // key_share
            0x4469, // application_settings (ALPS)
            0xfe0d, // encrypted_client_hello
            0xff01, // renegotiation_info
        ],
        ClientHelloProfile::FirefoxStable => &[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x0033,
            0x002b, 0x002d, 0x000d, 0x001b, 0xfe0d,
        ],
        ClientHelloProfile::RustlsDefault => &[],
    }
}

pub fn fingerprint_status_message() -> &'static str {
    "TLS FP: suite/kx/sig/ALPN via CryptoProvider; extension order still rustls-randomized (need craftls/uTLS for JA3/JA4)"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_has_order() {
        assert!(!intended_extension_order(ClientHelloProfile::ChromeStable).is_empty());
        assert!(!FingerprintBudget::RUSTLS_PARTIAL.extension_order);
    }
}
