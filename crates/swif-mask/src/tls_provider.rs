//! Pack-driven rustls CryptoProvider profiles (partial ClientHello FP).
//!
//! Reorders TLS 1.3 cipher suites, kx groups, and signature-scheme preference.
//! Does **not** rewrite extension order (needs uTLS/craftls). See `tls_fingerprint`.

use std::sync::Arc;

use rustls::crypto::{CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use rustls::pki_types::SignatureVerificationAlgorithm;
use rustls::{SignatureScheme, SupportedCipherSuite};

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

fn prefer_kx(
    base: &CryptoProvider,
    names: &[rustls::NamedGroup],
) -> Vec<&'static dyn SupportedKxGroup> {
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

/// Reorder `mapping` (drives offered signature_algorithms) without dropping schemes.
fn prefer_sig_schemes(
    base: WebPkiSupportedAlgorithms,
    prefer: &[SignatureScheme],
) -> WebPkiSupportedAlgorithms {
    let mut entries: Vec<(
        SignatureScheme,
        &'static [&'static dyn SignatureVerificationAlgorithm],
    )> = Vec::new();

    for want in prefer {
        if let Some(e) = base.mapping.iter().find(|(s, _)| s == want) {
            entries.push(*e);
        }
    }
    for e in base.mapping {
        if !entries.iter().any(|(s, _)| s == &e.0) {
            entries.push(*e);
        }
    }
    let mapping: &'static [_] = Box::leak(entries.into_boxed_slice());
    WebPkiSupportedAlgorithms {
        all: base.all,
        mapping,
    }
}

fn chrome_sig(base: WebPkiSupportedAlgorithms) -> WebPkiSupportedAlgorithms {
    prefer_sig_schemes(
        base,
        &[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
    )
}

fn firefox_sig(base: WebPkiSupportedAlgorithms) -> WebPkiSupportedAlgorithms {
    prefer_sig_schemes(
        base,
        &[
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ],
    )
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
            p.signature_verification_algorithms = chrome_sig(p.signature_verification_algorithms);
        }
        ClientHelloProfile::FirefoxStable => {
            p.cipher_suites = firefox_suites(&p);
            p.kx_groups = prefer_kx(
                &p,
                &[rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1],
            );
            p.signature_verification_algorithms = firefox_sig(p.signature_verification_algorithms);
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
        assert_eq!(
            p.signature_verification_algorithms.mapping[0].0,
            SignatureScheme::ECDSA_NISTP256_SHA256
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
