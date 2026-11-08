//! ClientHello fingerprint budget (honest uTLS status).
//!
//! rustls randomizes extension *positions* and does **not** expose fixed browser
//! extension order (no JA3/JA4 clone). Pack profiles still document the intended
//! order for agents / future craftls-class stacks.
//!
//! Note: upstream `craftls` tracks rustls **0.22** and cannot patch our 0.23 +
//! quinn stack today without a dual-TLS split.

use serde_json::{json, Value};

use crate::tls_profile::{ClientHelloProfile, TlsPackHints};
use crate::tls_provider::suite_order_ids;

/// What SwifWire controls today vs what needs a uTLS-class stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FingerprintBudget {
    pub cipher_suites: bool,
    pub kx_groups: bool,
    pub signature_schemes: bool,
    pub alpn: bool,
    pub grease_flag: bool,
    /// Fixed browser extension order — **false** on rustls.
    pub extension_order: bool,
}

impl FingerprintBudget {
    pub const RUSTLS_PARTIAL: Self = Self {
        cipher_suites: true,
        kx_groups: true,
        signature_schemes: true,
        alpn: true,
        grease_flag: true,
        extension_order: false,
    };
}

/// Intended TLS extension type ids (IANA) for a browser-like ClientHello.
/// Not applied by rustls; consumed by docs / future binders.
pub fn intended_extension_order(profile: ClientHelloProfile) -> &'static [u16] {
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
    "TLS FP: suite/kx/sig/ALPN via CryptoProvider; extension order still rustls-randomized (craftls 0.22 incompatible with rustls 0.23/quinn)"
}

/// Machine-readable ClientHello *intent* for pack validation / LLM agents.
/// This is **not** a captured wire ClientHello.
pub fn client_hello_intent(hints: &TlsPackHints) -> Value {
    let budget = FingerprintBudget::RUSTLS_PARTIAL;
    json!({
        "profile": hints.profile.as_str(),
        "alpn": hints.alpn,
        "grease": hints.grease,
        "sni_pool_ref": hints.sni_pool_ref,
        "cipher_suites": suite_order_ids(hints.profile),
        "intended_extension_order_iana": intended_extension_order(hints.profile),
        "budget": {
            "cipher_suites": budget.cipher_suites,
            "kx_groups": budget.kx_groups,
            "signature_schemes": budget.signature_schemes,
            "alpn": budget.alpn,
            "grease_flag": budget.grease_flag,
            "extension_order": budget.extension_order,
        },
        "craft_encoder": true,
        "craft_dial_wired": false,
        "status": fingerprint_status_message(),
        "craft_status": crate::tls_ch_wire::craft_status_message(),
    })
}

pub fn client_hello_intent_json(hints: &TlsPackHints) -> String {
    client_hello_intent(hints).to_string()
}

/// Partial JA3-like digest over **controlled** components only (suites + ALPN).
/// Not a real browser JA3 — extension order is missing. For pack/ops dashboards.
pub fn partial_ja3_label(hints: &TlsPackHints) -> String {
    let suites = suite_order_ids(hints.profile).join("-");
    let alpn = hints.alpn.join(",");
    format!(
        "swif-partial;profile={};suites={};alpn={};ext_order=rustls_random",
        hints.profile.as_str(),
        suites,
        alpn
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_has_order() {
        assert!(!intended_extension_order(ClientHelloProfile::ChromeStable).is_empty());
        assert!(!FingerprintBudget::RUSTLS_PARTIAL.extension_order);
    }

    #[test]
    fn intent_json_has_budget() {
        let hints = TlsPackHints::default();
        let v = client_hello_intent(&hints);
        assert_eq!(v["profile"], "chrome_stable");
        assert_eq!(v["budget"]["extension_order"], false);
        assert!(v["intended_extension_order_iana"].as_array().unwrap().len() > 5);
    }
}
