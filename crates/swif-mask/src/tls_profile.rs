//! Pack-driven TLS ClientHello / ALPN preferences (WP2C).
//!
//! Full browser JA3/JA4 mimicry needs a uTLS-class stack; rustls cannot reorder
//! extensions arbitrarily. This module applies what rustls allows today (ALPN,
//! named profile id for future binders) and records pack metadata for DialPolicy.

use serde::{Deserialize, Serialize};

use crate::pack::MaskProfile;

/// Named ClientHello intent from mask pack (not a byte-perfect browser clone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClientHelloProfile {
    #[default]
    RustlsDefault,
    ChromeStable,
    FirefoxStable,
}

impl ClientHelloProfile {
    pub fn parse(s: &str) -> Self {
        match s {
            "chrome_stable" => Self::ChromeStable,
            "firefox_stable" => Self::FirefoxStable,
            _ => Self::RustlsDefault,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RustlsDefault => "rustls_default",
            Self::ChromeStable => "chrome_stable",
            Self::FirefoxStable => "firefox_stable",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsPackHints {
    pub profile: ClientHelloProfile,
    pub alpn: Vec<String>,
    pub grease: bool,
    pub sni_pool_ref: Option<String>,
}

impl Default for TlsPackHints {
    fn default() -> Self {
        Self {
            profile: ClientHelloProfile::RustlsDefault,
            alpn: vec!["h2".into(), "http/1.1".into()],
            grease: true,
            sni_pool_ref: None,
        }
    }
}

impl TlsPackHints {
    pub fn from_mask_profile(p: &MaskProfile) -> Self {
        let mut h = Self::default();
        if let Some(prof) = p
            .templates
            .get("client_hello_profile")
            .and_then(|v| v.as_str())
        {
            h.profile = ClientHelloProfile::parse(prof);
        }
        if let Some(g) = p.templates.get("grease").and_then(|v| v.as_bool()) {
            h.grease = g;
        }
        if let Some(arr) = p.templates.get("alpn").and_then(|v| v.as_array()) {
            let list: Vec<String> = arr
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect();
            if !list.is_empty() {
                h.alpn = list;
            }
        }
        if let Some(cover) = &p.cover {
            if let Some(arr) = cover.get("alpn").and_then(|v| v.as_array()) {
                let list: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                if !list.is_empty() {
                    h.alpn = list;
                }
            }
            h.sni_pool_ref = cover
                .get("sni_pool_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
        // Chrome/Firefox intents prefer h2 first when pack omitted ALPN.
        if matches!(
            h.profile,
            ClientHelloProfile::ChromeStable | ClientHelloProfile::FirefoxStable
        ) && h.alpn.is_empty()
        {
            h.alpn = vec!["h2".into(), "http/1.1".into()];
        }
        h
    }

    pub fn alpn_wire(&self) -> Vec<Vec<u8>> {
        self.alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_chrome_hints() {
        let p = MaskProfile {
            id: "tls13_stable".into(),
            underlay: "tcp".into(),
            default_port: Some(443),
            shaper: json!({}),
            templates: json!({
                "client_hello_profile": "chrome_stable",
                "grease": true,
                "alpn": ["h2", "http/1.1"]
            }),
            cover: Some(json!({"sni_pool_ref": "pool.v1"})),
        };
        let h = TlsPackHints::from_mask_profile(&p);
        assert_eq!(h.profile, ClientHelloProfile::ChromeStable);
        assert_eq!(h.alpn, vec!["h2", "http/1.1"]);
        assert_eq!(h.sni_pool_ref.as_deref(), Some("pool.v1"));
    }
}
