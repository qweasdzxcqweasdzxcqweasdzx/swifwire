//! Pack-driven rustls CryptoProvider profiles (partial ClientHello FP).
//!
//! Reorders TLS 1.3 cipher suites and kx groups. Does **not** rewrite extension
//! order (needs uTLS-class stack). Improves JA3 suite/curve components vs default.

use std::sync::Arc;

use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::SupportedCipherSuite;

use crate::tls_profile::ClientHelloProfile;

fn ring_default() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

/// Chrome-like preference: AES-128-GCM, CHACHA20, AES-256-GCM; X25519 then P-256.
fn chrome_suites(base: &CryptoProvider) -> Vec<SupportedCipherSuite> {
    prefer_suites(
        base,
        &[
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        ],
    )
}

/// Firefox-like: CHACHA first, then AES-128, AES-256.
fn firefox_suites(base: &CryptoProvider) -> Vec<SupportedCipherSuite> {
    prefer_suites(
        base,
        &[
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        ],
    )
}

fn prefer_suites(
    base: &CryptoProvider,
    order: &[rustls::CipherSuite],
) -> Vec<SupportedCipherSuite> {
    let mut out = Vec::new();
    for want in order {
        if let Some(s) = base
            .cipher_suites
            .iter()
            .find(|s| s.suite() == *want)
            .copied()
        {
            out.push(s);
        }
    }
    for s in &base.cipher_suites {
        if !out.iter().any(|x| x.suite() == s.suite()) {
            out.push(*s);
        }
    }
    out
}

fn prefer_kx(base: &CryptoProvider, names: &[rustls::NamedGroup]) -> Vec<&'static dyn SupportedKxGroup> {
    let mut out: Vec<&'static dyn SupportedKxGroup> = Vec::new();
    for want in names {
        if let Some(g) = base.kx_groups.iter().find(|g| g.name() == *want).copied() {
            out.push(g);
        }
    }
    for g in &base.kx_groups {
        if !out.iter().any(|x| x.name() == g.name()) {
            out.push(*g);
        }
    }
    out
}

pub fn provider_for_profile(profile: ClientHelloProfile) -> Arc<CryptoProvider> {
    let mut p = ring_default();
    match profile {
        ClientHelloProfile::RustlsDefault => {}
        ClientHelloProfile::ChromeStable => {
            p.cipher_suites = chrome_suites(&p);
            p.kx_groups = prefer_kx(
                &p,
                &[rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1],
            );
        }
        ClientHelloProfile::FirefoxStable => {
            p.cipher_suites = firefox_suites(&p);
            p.kx_groups = prefer_kx(
                &p,
                &[rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1],
            );
        }
    }
    Arc::new(p)
}

pub fn suite_order_ids(profile: ClientHelloProfile) -> Vec<&'static str> {
    match profile {
        ClientHelloProfile::RustlsDefault => vec!["provider_default"],
        ClientHelloProfile::ChromeStable => {
            vec!["TLS13_AES_128_GCM_SHA256", "TLS13_CHACHA20", "TLS13_AES_256_GCM"]
        }
        ClientHelloProfile::FirefoxStable => {
            vec!["TLS13_CHACHA20", "TLS13_AES_128_GCM_SHA256", "TLS13_AES_256_GCM"]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_provider_builds() {
        let p = provider_for_profile(ClientHelloProfile::ChromeStable);
        assert!(!p.cipher_suites.is_empty());
        assert_eq!(
            p.cipher_suites[0].suite(),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        );
    }

    #[test]
    fn firefox_chacha_first() {
        let p = provider_for_profile(ClientHelloProfile::FirefoxStable);
        assert_eq!(
            p.cipher_suites[0].suite(),
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
    }
}
