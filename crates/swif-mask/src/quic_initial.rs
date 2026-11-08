//! Pack-driven QUIC Initial template (WP3).
//!
//! ## Wire in pack
//! Prefer structured `templates.quic_initial` JSON. Optional opaque
//! `templates.quic_initial_b64` holds a compact binary blob (`SQI1`…) for
//! ops that capture real browser Initial headers.
//!
//! Quinn does not yet accept a full forged Initial; fields drive grease /
//! DCID policy on `quic_lab` and ALPN/SNI hints on `quic_stable`.

use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pack::MaskProfile;

pub const MAGIC: &[u8; 4] = b"SQI1";
pub const TEMPLATE_FORMAT: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicInitialTemplate {
    /// Preferred QUIC version (0 = use grease pool only).
    #[serde(default)]
    pub version: u32,
    /// Destination CID length hint (4..=20).
    #[serde(default = "default_dcid_len")]
    pub dcid_len: u8,
    /// Source CID length hint.
    #[serde(default)]
    pub scid_len: u8,
    /// Extra grease version candidates (wire BE in binary form).
    #[serde(default)]
    pub grease_versions: Vec<u32>,
    /// Minimum UDP payload pad after Initial cover (lab).
    #[serde(default)]
    pub pad_hint: u16,
    /// True when pack included a non-empty opaque `quic_initial_b64`.
    #[serde(default)]
    pub has_opaque: bool,
    /// Opaque raw bytes from `quic_initial_b64` (may be SQI1 or capture).
    #[serde(default, skip_serializing)]
    pub opaque: Vec<u8>,
}

fn default_dcid_len() -> u8 {
    8
}

impl Default for QuicInitialTemplate {
    fn default() -> Self {
        Self {
            version: 0x0000_0001,
            dcid_len: 8,
            scid_len: 0,
            grease_versions: vec![0x6b33_1efd, 0xface_b001, 0x0a0a_0a0a],
            pad_hint: 0,
            has_opaque: false,
            opaque: Vec::new(),
        }
    }
}

impl QuicInitialTemplate {
    pub fn from_mask_profile(p: &MaskProfile) -> Self {
        let mut t = Self::default();
        if let Some(obj) = p.templates.get("quic_initial") {
            if let Ok(parsed) = serde_json::from_value::<QuicInitialTemplateJson>(obj.clone()) {
                t.version = parsed.version.unwrap_or(t.version);
                t.dcid_len = parsed.dcid_len.unwrap_or(t.dcid_len).clamp(4, 20);
                t.scid_len = parsed.scid_len.unwrap_or(t.scid_len).min(20);
                if let Some(g) = parsed.grease_versions {
                    if !g.is_empty() {
                        t.grease_versions = g;
                    }
                }
                t.pad_hint = parsed.pad_hint.unwrap_or(t.pad_hint);
            }
        }
        if let Some(b64) = p
            .templates
            .get("quic_initial_b64")
            .and_then(|v| v.as_str())
        {
            if !b64.is_empty() {
                if let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(b64) {
                    t.has_opaque = !raw.is_empty();
                    if let Some(parsed) = Self::parse_sqi1(&raw) {
                        // Structured SQI1 overrides JSON defaults.
                        t = parsed;
                        t.has_opaque = true;
                        t.opaque = raw;
                    } else {
                        t.opaque = raw;
                    }
                }
            }
        }
        t
    }

    /// Encode compact SQI1 binary for pack authors.
    pub fn encode_sqi1(&self) -> Vec<u8> {
        let grease = &self.grease_versions;
        let n = grease.len().min(16);
        let mut out = Vec::with_capacity(4 + 1 + 4 + 1 + 1 + 1 + 2 + 4 * n);
        out.extend_from_slice(MAGIC);
        out.push(TEMPLATE_FORMAT);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.dcid_len.clamp(4, 20));
        out.push(self.scid_len.min(20));
        out.push(n as u8);
        out.extend_from_slice(&self.pad_hint.to_be_bytes());
        for v in grease.iter().take(n) {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out
    }

    pub fn encode_sqi1_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.encode_sqi1())
    }

    pub fn parse_sqi1(raw: &[u8]) -> Option<Self> {
        if raw.len() < 4 + 1 + 4 + 1 + 1 + 1 + 2 {
            return None;
        }
        if &raw[0..4] != MAGIC {
            return None;
        }
        if raw[4] != TEMPLATE_FORMAT {
            return None;
        }
        let version = u32::from_be_bytes(raw[5..9].try_into().ok()?);
        let dcid_len = raw[9].clamp(4, 20);
        let scid_len = raw[10].min(20);
        let n = raw[11] as usize;
        let pad_hint = u16::from_be_bytes(raw[12..14].try_into().ok()?);
        let need = 14 + 4 * n;
        if raw.len() < need || n > 16 {
            return None;
        }
        let mut grease_versions = Vec::with_capacity(n);
        for i in 0..n {
            let o = 14 + 4 * i;
            grease_versions.push(u32::from_be_bytes(raw[o..o + 4].try_into().ok()?));
        }
        Some(Self {
            version,
            dcid_len,
            scid_len,
            grease_versions,
            pad_hint,
            has_opaque: true,
            opaque: raw.to_vec(),
        })
    }

    pub fn pick_grease_version(&self) -> u32 {
        if self.grease_versions.is_empty() {
            return if self.version != 0 {
                self.version
            } else {
                0x0000_0001
            };
        }
        let i = (rand::random::<usize>()) % self.grease_versions.len();
        self.grease_versions[i]
    }

    pub fn random_dcid(&self) -> Vec<u8> {
        let n = self.dcid_len.clamp(4, 20) as usize;
        let mut id = vec![0u8; n];
        rand::thread_rng().fill_bytes(&mut id);
        id
    }

    /// JSON snippet for agents / CLIENT_SDK.
    pub fn to_pack_value(&self) -> Value {
        serde_json::json!({
            "version": self.version,
            "dcid_len": self.dcid_len,
            "scid_len": self.scid_len,
            "grease_versions": self.grease_versions,
            "pad_hint": self.pad_hint,
            "has_opaque": self.has_opaque,
        })
    }
}

#[derive(Debug, Deserialize)]
struct QuicInitialTemplateJson {
    version: Option<u32>,
    dcid_len: Option<u8>,
    scid_len: Option<u8>,
    grease_versions: Option<Vec<u32>>,
    pad_hint: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sqi1_roundtrip() {
        let t = QuicInitialTemplate {
            version: 1,
            dcid_len: 12,
            scid_len: 0,
            grease_versions: vec![0x6b33_1efd, 0xface_b001],
            pad_hint: 32,
            has_opaque: false,
            opaque: vec![],
        };
        let raw = t.encode_sqi1();
        let back = QuicInitialTemplate::parse_sqi1(&raw).unwrap();
        assert_eq!(back.version, 1);
        assert_eq!(back.dcid_len, 12);
        assert_eq!(back.grease_versions, t.grease_versions);
        assert_eq!(back.pad_hint, 32);
    }

    #[test]
    fn from_pack_json_and_b64() {
        let t0 = QuicInitialTemplate {
            version: 1,
            dcid_len: 8,
            scid_len: 0,
            grease_versions: vec![0x0a0a_0a0a],
            pad_hint: 0,
            has_opaque: false,
            opaque: vec![],
        };
        let p = MaskProfile {
            id: "quic_stable".into(),
            underlay: "udp".into(),
            default_port: Some(443),
            shaper: json!({}),
            templates: json!({
                "quic_initial": {
                    "version": 1,
                    "dcid_len": 10,
                    "grease_versions": [1, 2, 3]
                },
                "quic_initial_b64": t0.encode_sqi1_b64()
            }),
            cover: None,
        };
        // b64 SQI1 wins over JSON object.
        let t = QuicInitialTemplate::from_mask_profile(&p);
        assert_eq!(t.dcid_len, 8);
        assert!(t.has_opaque);
        assert_eq!(t.grease_versions, vec![0x0a0a_0a0a]);
    }
}
