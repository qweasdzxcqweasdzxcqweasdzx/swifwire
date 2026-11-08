//! Embeddable SwifWire core for VPN clients and panel sidecars (3x-ui style).

mod config;
mod policy;
mod runtime;

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use swif_crypto::PackVerifyingKey;
use swif_mask::{verify_and_load, MaskPack};
use thiserror::Error;

pub use config::{
    Inbound, InboundClient, InboundSettings, Outbound, OutboundSettings, ShareLink,
};
pub use policy::{DialPolicy, MaskId};
use runtime::RuntimeEngine;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0}")]
    Msg(String),
    #[error("pack: {0}")]
    Pack(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    #[serde(default)]
    pub outbound: Option<Outbound>,
    #[serde(default)]
    pub server_addr: Option<String>,
    #[serde(default)]
    pub server_static_pub_hex: Option<String>,
    #[serde(default)]
    pub mask_profile: Option<String>,
    #[serde(default)]
    pub socks_listen: Option<String>,
    #[serde(default)]
    pub pack_trust_pub_hex: Option<String>,
    #[serde(default)]
    pub tls_material_path: Option<String>,
    /// `pin` (lab) or `webpki` (prod).
    #[serde(default)]
    pub tls_verify: Option<String>,
    #[serde(default)]
    pub legacy_fallback_uri: Option<String>,
    /// If true (default), start local SOCKS → edge tunnel.
    #[serde(default = "default_true")]
    pub start_runtime: bool,
    #[serde(default = "default_route")]
    pub route_mode: String,
}

fn default_true() -> bool {
    true
}

fn default_route() -> String {
    "global".into()
}

impl CoreConfig {
    pub fn resolved_outbound(&self) -> Result<Outbound, CoreError> {
        if let Some(o) = &self.outbound {
            return Ok(o.clone());
        }
        let addr = self
            .server_addr
            .clone()
            .ok_or_else(|| CoreError::Msg("server_addr or outbound required".into()))?;
        let (host, port) = if let Some((h, p)) = addr.rsplit_once(':') {
            (
                h.to_string(),
                p.parse()
                    .map_err(|_| CoreError::Msg("bad server_addr port".into()))?,
            )
        } else {
            return Err(CoreError::Msg("server_addr host:port".into()));
        };
        let pub_hex = self
            .server_static_pub_hex
            .clone()
            .ok_or_else(|| CoreError::Msg("server_static_pub_hex required".into()))?;
        Ok(Outbound {
            protocol: "swifwire".into(),
            tag: None,
            settings: OutboundSettings {
                address: host,
                port,
                server_pub_hex: pub_hex,
                mask: self
                    .mask_profile
                    .clone()
                    .unwrap_or_else(|| "tls13_stable".into()),
                sni: None,
                socks_listen: self
                    .socks_listen
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1:10808".into()),
                pack_url: None,
                pack_trust_pub_hex: self.pack_trust_pub_hex.clone(),
                tls_material_path: self.tls_material_path.clone(),
                tls_verify: self
                    .tls_verify
                    .clone()
                    .unwrap_or_else(|| "pin".into()),
                legacy_fallback_uri: self.legacy_fallback_uri.clone(),
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreStatus {
    pub state: String,
    pub mask: String,
    pub pack_id: Option<String>,
    pub route_mode: String,
    pub socks_listen: Option<String>,
    pub server: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub last_error: Option<String>,
    /// Configured legacy URI (host app dials when SwifWire exhausts).
    #[serde(default)]
    pub legacy_fallback_hint: Option<String>,
    /// Honest FP: extension order not controlled by rustls.
    #[serde(default)]
    pub tls_extension_order_ready: bool,
    /// Quinn `quic_stable` dial/accept compiled in.
    #[serde(default)]
    pub quic_stable_runtime_ready: bool,
    /// Core/protocol commercial test gate version string.
    #[serde(default)]
    pub prod_gate: String,
}

pub struct CoreHandle {
    inner: Mutex<CoreInner>,
}

struct CoreInner {
    config: CoreConfig,
    outbound: Outbound,
    pack: Option<MaskPack>,
    tls_hints: swif_mask::TlsPackHints,
    quic_hints: swif_mask::QuicStableHints,
    policy: DialPolicy,
    status: CoreStatus,
    engine: Option<RuntimeEngine>,
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn core_version() -> String {
    version().to_string()
}

pub fn core_start(config_json: &str) -> Result<CoreHandle, CoreError> {
    let config: CoreConfig =
        serde_json::from_str(config_json).map_err(|e| CoreError::Msg(e.to_string()))?;
    let outbound = config.resolved_outbound()?;
    let mask = outbound.settings.mask.clone();
    let socks = outbound.settings.socks_listen.clone();
    let server = format!("{}:{}", outbound.settings.address, outbound.settings.port);
    let route_mode = config.route_mode.clone();
    let start_rt = config.start_runtime;
    let tls_hints = swif_mask::TlsPackHints::default();
    let quic_hints = swif_mask::QuicStableHints::default();
    let engine = if start_rt {
        Some(RuntimeEngine::spawn_with_hints(
            outbound.clone(),
            crate::runtime::RuntimeHints {
                tls: tls_hints.clone(),
                quic: quic_hints.clone(),
            },
        )?)
    } else {
        None
    };
    let state = if start_rt {
        "running".into()
    } else {
        "started".into()
    };
    let legacy = outbound.settings.legacy_fallback_uri.clone();
    Ok(CoreHandle {
        inner: Mutex::new(CoreInner {
            config,
            outbound,
            pack: None,
            tls_hints,
            quic_hints,
            policy: DialPolicy::default(),
            engine,
            status: CoreStatus {
                state,
                mask,
                pack_id: None,
                route_mode,
                socks_listen: Some(socks),
                server: Some(server),
                bytes_up: 0,
                bytes_down: 0,
                last_error: None,
                legacy_fallback_hint: legacy,
                tls_extension_order_ready: false,
                quic_stable_runtime_ready: swif_mask::quic_stable_ready(),
                prod_gate: "0.4.0-prod".into(),
            },
        }),
    })
}

/// Host dual-stack: opaque legacy share URI from config (not executed by core).
pub fn core_legacy_fallback_uri(handle: &CoreHandle) -> Result<Option<String>, CoreError> {
    let g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    Ok(g.outbound
        .settings
        .legacy_fallback_uri
        .clone()
        .or_else(|| g.status.legacy_fallback_hint.clone()))
}

pub fn core_stop(handle: CoreHandle) {
    if let Ok(mut g) = handle.inner.lock() {
        if let Some(eng) = g.engine.take() {
            eng.shutdown();
        }
        g.status.state = "stopped".into();
    }
}

pub fn core_set_route_mode(handle: &CoreHandle, mode: &str) -> Result<(), CoreError> {
    let mut g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    g.config.route_mode = mode.to_string();
    g.status.route_mode = mode.to_string();
    Ok(())
}

pub fn core_import_subscription(handle: &CoreHandle, url_or_blob: &str) -> Result<(), CoreError> {
    let mut g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    let outbound = if url_or_blob.trim_start().starts_with('{') {
        Outbound::parse_json(url_or_blob)?
    } else if url_or_blob.contains("swif://") {
        // may be multi-line subscription
        let line = url_or_blob
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("swif://"))
            .ok_or_else(|| CoreError::Msg("no swif:// in subscription".into()))?;
        Outbound::from_uri(line)?
    } else {
        Outbound::from_uri(url_or_blob.trim())?
    };
    g.status.mask = outbound.settings.mask.clone();
    g.status.socks_listen = Some(outbound.settings.socks_listen.clone());
    g.status.server = Some(format!(
        "{}:{}",
        outbound.settings.address, outbound.settings.port
    ));
    g.status.state = "subscribed".into();
    g.outbound = outbound;
    Ok(())
}

pub fn core_apply_mask_pack(handle: &CoreHandle, bytes: &[u8]) -> Result<(), CoreError> {
    let mut g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    let trust_hex = g
        .outbound
        .settings
        .pack_trust_pub_hex
        .clone()
        .or_else(|| g.config.pack_trust_pub_hex.clone())
        .ok_or_else(|| CoreError::Msg("pack_trust_pub_hex missing".into()))?;
    let raw = hex::decode(trust_hex.trim()).map_err(|e| CoreError::Msg(e.to_string()))?;
    if raw.len() != 32 {
        return Err(CoreError::Msg("trust pub must be 32 bytes".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    let vk = PackVerifyingKey::from_bytes(arr).map_err(|e| CoreError::Pack(e.to_string()))?;
    let pack = verify_and_load(bytes, &vk).map_err(|e| CoreError::Pack(e.to_string()))?;
    g.status.pack_id = Some(pack.pack_id.clone());
    let preferred = g.outbound.settings.mask.clone();
    let prof = pack
        .profile(&preferred)
        .ok()
        .or_else(|| pack.profile("tls13_stable").ok())
        .or_else(|| pack.profile("quic_stable").ok())
        .or_else(|| pack.profiles.first());
    if let Some(p) = prof {
        g.status.mask = p.id.clone();
        g.outbound.settings.mask = p.id.clone();
        g.policy.on_mask_offer(&p.id);
        let hints = swif_mask::TlsPackHints::from_mask_profile(p);
        let qhints = swif_mask::QuicStableHints::from_mask_profile(p);
        tracing::info!(
            "mask pack {} profile={} hello={} quic_initial={}",
            pack.pack_id,
            p.id,
            hints.profile.as_str(),
            qhints.has_initial_template
        );
        tracing::debug!(
            "client_hello_intent={}",
            swif_mask::client_hello_intent_json(&hints)
        );
        g.tls_hints = hints;
        g.quic_hints = qhints;
    }
    g.pack = Some(pack);
    g.status.state = "pack_applied".into();
    // Hot-apply: restart runtime with new pack hints if it was running.
    if g.engine.is_some() {
        if let Some(eng) = g.engine.take() {
            eng.shutdown();
        }
        g.engine = Some(crate::runtime::RuntimeEngine::spawn_with_hints(
            g.outbound.clone(),
            crate::runtime::RuntimeHints {
                tls: g.tls_hints.clone(),
                quic: g.quic_hints.clone(),
            },
        )?);
        g.status.state = "pack_applied_restarted".into();
    }
    Ok(())
}

pub fn core_status(handle: &CoreHandle) -> Result<String, CoreError> {
    let g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    serde_json::to_string(&g.status).map_err(|e| CoreError::Msg(e.to_string()))
}

pub fn core_outbound_json(handle: &CoreHandle) -> Result<String, CoreError> {
    let g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    serde_json::to_string(&g.outbound).map_err(|e| CoreError::Msg(e.to_string()))
}

/// Panel helper: parse inbound JSON → edge argv JSON array.
pub fn panel_inbound_edge_argv(inbound_json: &str) -> Result<String, CoreError> {
    let ib = Inbound::parse_json(inbound_json)?;
    serde_json::to_string(&ib.edge_argv()).map_err(|e| CoreError::Msg(e.to_string()))
}

/// Panel helper: build share URI for a client.
pub fn panel_share_uri(
    inbound_json: &str,
    public_host: &str,
    server_pub_hex: &str,
    remark: &str,
) -> Result<String, CoreError> {
    let ib = Inbound::parse_json(inbound_json)?;
    let share = ib.share_for(public_host, server_pub_hex, remark);
    Ok(share.uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use swif_crypto::PackSigningKey;
    use swif_mask::sign_pack_value;

    #[test]
    fn start_import_status() {
        let cfg = serde_json::json!({
            "server_addr": "1.2.3.4:443",
            "server_static_pub_hex": "ab".repeat(32),
            "mask_profile": "tls13_stable",
            "socks_listen": "127.0.0.1:10808",
            "start_runtime": false
        });
        let h = core_start(&cfg.to_string()).unwrap();
        core_set_route_mode(&h, "rule").unwrap();
        let uri = format!(
            "swif://node.example:8443?pub={}&mask=quic_fast",
            "cd".repeat(32)
        );
        core_import_subscription(&h, &uri).unwrap();
        let st = core_status(&h).unwrap();
        assert!(st.contains("quic_fast"));
        assert!(st.contains("subscribed") || st.contains("node.example"));
        core_stop(h);
    }

    #[test]
    fn pack_apply() {
        let sk = PackSigningKey::generate();
        let vk = sk.verifying_key();
        let raw = serde_json::json!({
            "format": 1,
            "pack_id": "smoke",
            "min_core": "0.1.0",
            "profiles": [{
                "id": "tls13_stable",
                "underlay": "tcp",
                "shaper": {"length_hist":[{"bytes":64,"weight":1}],"idle_ms":1},
                "templates": {}
            }],
            "signature": {"alg":"ed25519","key_id":"x","sig_b64":"AA"}
        });
        let signed = sign_pack_value(raw, &sk, "dev").unwrap();
        let bytes = serde_json::to_vec(&signed).unwrap();
        let cfg = serde_json::json!({
            "server_addr": "127.0.0.1:9443",
            "server_static_pub_hex": "ab".repeat(32),
            "pack_trust_pub_hex": hex::encode(vk.to_bytes()),
            "start_runtime": false
        });
        let h = core_start(&cfg.to_string()).unwrap();
        core_apply_mask_pack(&h, &bytes).unwrap();
        assert!(core_status(&h).unwrap().contains("smoke"));
        core_stop(h);
    }

    #[test]
    fn legacy_uri_exposed() {
        let cfg = serde_json::json!({
            "server_addr": "1.2.3.4:443",
            "server_static_pub_hex": "ab".repeat(32),
            "legacy_fallback_uri": "vless://example",
            "start_runtime": false
        });
        let h = core_start(&cfg.to_string()).unwrap();
        assert_eq!(
            core_legacy_fallback_uri(&h).unwrap().as_deref(),
            Some("vless://example")
        );
        let st: CoreStatus = serde_json::from_str(&core_status(&h).unwrap()).unwrap();
        assert_eq!(st.legacy_fallback_hint.as_deref(), Some("vless://example"));
        assert!(st.quic_stable_runtime_ready);
        assert!(!st.tls_extension_order_ready);
        assert_eq!(st.prod_gate, "0.4.0-prod");
        core_stop(h);
    }

    #[test]
    fn panel_helpers() {
        let ib = r#"{"protocol":"swifwire","port":443,"settings":{"static_key_path":"k","mask":"tls13_stable"}}"#;
        let argv = panel_inbound_edge_argv(ib).unwrap();
        assert!(argv.contains("tls13_stable"));
        let uri = panel_share_uri(ib, "vpn.example.com", &"ab".repeat(32), "c1").unwrap();
        assert!(uri.starts_with("swif://vpn.example.com:443?"));
    }
}
