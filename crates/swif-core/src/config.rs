//! Embed configs: client outbound, panel inbound, subscription URI.

use serde::{Deserialize, Serialize};

use crate::CoreError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSettings {
    pub address: String,
    pub port: u16,
    pub server_pub_hex: String,
    #[serde(default = "default_mask")]
    pub mask: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default = "default_socks")]
    pub socks_listen: String,
    #[serde(default)]
    pub pack_url: Option<String>,
    #[serde(default)]
    pub pack_trust_pub_hex: Option<String>,
    /// Path to lab-cert.der.json for tls13_stable (same as swif-cli --tls-material).
    #[serde(default)]
    pub tls_material_path: Option<String>,
    /// `pin` (lab default) | `webpki` (prod public CA).
    #[serde(default = "default_tls_verify")]
    pub tls_verify: String,
    /// Phase-1 dual-stack: opaque legacy outbound URI (vless://… etc.) — not parsed by SwifWire.
    #[serde(default)]
    pub legacy_fallback_uri: Option<String>,
}

fn default_tls_verify() -> String {
    "pin".into()
}

fn default_mask() -> String {
    "tls13_stable".into()
}
fn default_socks() -> String {
    "127.0.0.1:10808".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Outbound {
    pub protocol: String,
    #[serde(default)]
    pub tag: Option<String>,
    pub settings: OutboundSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundClient {
    pub email: String,
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub limit_ip: Option<u32>,
    #[serde(default)]
    pub total_gb: Option<f64>,
    #[serde(default)]
    pub expiry_time: Option<i64>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundSettings {
    pub static_key_path: String,
    #[serde(default = "default_pub")]
    pub pub_out_path: String,
    #[serde(default = "default_mask")]
    pub mask: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub cover: Option<String>,
    /// `direct` or `socks5://127.0.0.1:PORT` for Xray egress bridge.
    #[serde(default = "default_egress")]
    pub egress: String,
    #[serde(default)]
    pub clients: Vec<InboundClient>,
}

fn default_pub() -> String {
    "server.pub".into()
}
fn default_egress() -> String {
    "direct".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inbound {
    pub protocol: String,
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
    pub settings: InboundSettings,
}

fn default_listen() -> String {
    "0.0.0.0".into()
}

/// Panel-facing share for one client (subscription item).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLink {
    pub remark: String,
    pub uri: String,
    pub outbound: Outbound,
}

impl Outbound {
    pub fn parse_json(s: &str) -> Result<Self, CoreError> {
        let o: Self = serde_json::from_str(s).map_err(|e| CoreError::Msg(e.to_string()))?;
        if o.protocol != "swifwire" {
            return Err(CoreError::Msg("protocol must be swifwire".into()));
        }
        if o.settings.server_pub_hex.len() != 64 {
            return Err(CoreError::Msg("server_pub_hex must be 64 hex chars".into()));
        }
        Ok(o)
    }

    /// `swif://host:port?pub=HEX&mask=tls13_stable&sni=cover.local`
    pub fn to_uri(&self) -> String {
        let s = &self.settings;
        let mut q = format!("pub={}", s.server_pub_hex);
        q.push_str(&format!("&mask={}", s.mask));
        if let Some(sni) = &s.sni {
            q.push_str(&format!("&sni={}", urlencoding_lite(sni)));
        }
        format!("swif://{}:{}?{}", s.address, s.port, q)
    }

    pub fn from_uri(uri: &str) -> Result<Self, CoreError> {
        let uri = uri.trim();
        let rest = uri
            .strip_prefix("swif://")
            .ok_or_else(|| CoreError::Msg("need swif://".into()))?;
        let (hostport, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (address, port_s) = hostport
            .rsplit_once(':')
            .ok_or_else(|| CoreError::Msg("host:port required".into()))?;
        let port: u16 = port_s
            .parse()
            .map_err(|_| CoreError::Msg("bad port".into()))?;
        let mut server_pub_hex = String::new();
        let mut mask = default_mask();
        let mut sni = None;
        for part in query.split('&') {
            if part.is_empty() {
                continue;
            }
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            match k {
                "pub" => server_pub_hex = v.to_string(),
                "mask" => mask = v.to_string(),
                "sni" => sni = Some(v.to_string()),
                _ => {}
            }
        }
        if server_pub_hex.len() != 64 {
            return Err(CoreError::Msg("pub=64hex required".into()));
        }
        Ok(Self {
            protocol: "swifwire".into(),
            tag: None,
            settings: OutboundSettings {
                address: address.to_string(),
                port,
                server_pub_hex,
                mask,
                sni,
                socks_listen: default_socks(),
                pack_url: None,
                pack_trust_pub_hex: None,
                tls_material_path: None,
                tls_verify: default_tls_verify(),
                legacy_fallback_uri: None,
            },
        })
    }
}

impl Inbound {
    pub fn parse_json(s: &str) -> Result<Self, CoreError> {
        let i: Self = serde_json::from_str(s).map_err(|e| CoreError::Msg(e.to_string()))?;
        if i.protocol != "swifwire" {
            return Err(CoreError::Msg("protocol must be swifwire".into()));
        }
        Ok(i)
    }

    /// Build client share for panel subscription export.
    pub fn share_for(
        &self,
        public_host: &str,
        server_pub_hex: &str,
        remark: &str,
    ) -> ShareLink {
        let outbound = Outbound {
            protocol: "swifwire".into(),
            tag: self.tag.clone(),
            settings: OutboundSettings {
                address: public_host.to_string(),
                port: self.port,
                server_pub_hex: server_pub_hex.to_string(),
                mask: self.settings.mask.clone(),
                sni: self.settings.sni.clone(),
                socks_listen: default_socks(),
                pack_url: None,
                pack_trust_pub_hex: None,
                tls_material_path: None,
                tls_verify: default_tls_verify(),
                legacy_fallback_uri: None,
            },
        };
        ShareLink {
            remark: remark.to_string(),
            uri: outbound.to_uri(),
            outbound,
        }
    }

    /// Args for `swif-edge` process (3x-ui sidecar).
    pub fn edge_argv(&self) -> Vec<String> {
        let listen = format!("{}:{}", self.listen, self.port);
        let mut args = vec![
            "--listen".into(),
            listen,
            "--key".into(),
            self.settings.static_key_path.clone(),
            "--pub-out".into(),
            self.settings.pub_out_path.clone(),
            "--mask".into(),
            self.settings.mask.clone(),
        ];
        if let Some(sni) = &self.settings.sni {
            args.push("--sni".into());
            args.push(sni.clone());
        }
        if let Some(cover) = &self.settings.cover {
            args.push("--cover".into());
            args.push(cover.clone());
        }
        args
    }
}

fn urlencoding_lite(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_roundtrip() {
        let o = Outbound {
            protocol: "swifwire".into(),
            tag: Some("n1".into()),
            settings: OutboundSettings {
                address: "vpn.example.com".into(),
                port: 443,
                server_pub_hex: "ab".repeat(32),
                mask: "tls13_stable".into(),
                sni: Some("cdn.example.com".into()),
                socks_listen: "127.0.0.1:10808".into(),
                pack_url: None,
                pack_trust_pub_hex: None,
                tls_material_path: None,
                tls_verify: default_tls_verify(),
                legacy_fallback_uri: None,
            },
        };
        let uri = o.to_uri();
        assert!(uri.starts_with("swif://vpn.example.com:443?"));
        let back = Outbound::from_uri(&uri).unwrap();
        assert_eq!(back.settings.port, 443);
        assert_eq!(back.settings.mask, "tls13_stable");
        assert_eq!(back.settings.sni.as_deref(), Some("cdn.example.com"));
    }

    #[test]
    fn inbound_edge_argv() {
        let raw = r#"{
          "protocol":"swifwire","port":9443,
          "settings":{"static_key_path":"server.key","mask":"tls13_stable","sni":"cover.local"}
        }"#;
        let ib = Inbound::parse_json(raw).unwrap();
        let args = ib.edge_argv();
        assert!(args.contains(&"--mask".into()));
        assert!(args.contains(&"tls13_stable".into()));
    }
}
