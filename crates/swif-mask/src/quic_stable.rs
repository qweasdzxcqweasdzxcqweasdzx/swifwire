//! `quic_stable` — pack-driven QUIC-like underlay (WP3).
//!
//! ## Target framing (normative intent)
//! 1. Real QUIC 1-RTT (quinn) with pack-selected ALPN (`h3` or cover ALPN).
//! 2. Bidirectional QUIC stream 0 carries length-prefixed SwifHS + AEAD records
//!    (same pref framing as TCP masks).
//! 3. Datagrams map to QUIC datagrams when available.
//!
//! Status: **scaffold**. Runtime still uses greased `quic_lab`.  
//! Do not select as DialPolicy prod default until `is_runtime_ready()` is true.

use crate::pack::MaskProfile;

pub const PROFILE_ID: &str = "quic_stable";

#[derive(Debug, Clone)]
pub struct QuicStableHints {
    pub alpn: Vec<String>,
    pub sni_pool_ref: Option<String>,
    pub has_initial_template: bool,
}

impl Default for QuicStableHints {
    fn default() -> Self {
        Self {
            alpn: vec!["h3".into()],
            sni_pool_ref: None,
            has_initial_template: false,
        }
    }
}

impl QuicStableHints {
    pub fn from_mask_profile(p: &MaskProfile) -> Self {
        let mut h = Self::default();
        if let Some(b64) = p
            .templates
            .get("quic_initial_b64")
            .and_then(|v| v.as_str())
        {
            h.has_initial_template = !b64.is_empty();
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
        h
    }
}

/// True when a real QUIC stack + pack templates are wired (not yet).
pub fn is_runtime_ready() -> bool {
    false
}

/// Human-readable status for agents / CLIENT_SDK.
pub fn status_message() -> &'static str {
    "quic_stable scaffold: use quic_lab under SWIF_LAB/SWIF_ALLOW_QUIC_LAB until quinn pack path ships"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn not_ready() {
        assert!(!is_runtime_ready());
        assert!(!status_message().is_empty());
    }

    #[test]
    fn parses_hints() {
        let p = MaskProfile {
            id: PROFILE_ID.into(),
            underlay: "udp".into(),
            default_port: Some(443),
            shaper: json!({}),
            templates: json!({"quic_initial_b64": "AAAA"}),
            cover: Some(json!({"alpn": ["h3"], "sni_pool_ref": "q.v1"})),
        };
        let h = QuicStableHints::from_mask_profile(&p);
        assert!(h.has_initial_template);
        assert_eq!(h.alpn, vec!["h3"]);
    }
}
