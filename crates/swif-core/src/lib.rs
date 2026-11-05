//! High-level UI ↔ core API (UniFFI / C-ABI surface for M2 smoke).

mod policy;

use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use swif_crypto::PackVerifyingKey;
use swif_mask::{verify_and_load, MaskPack};
use thiserror::Error;

pub use policy::{DialPolicy, MaskId};

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("{0}")]
    Msg(String),
    #[error("pack: {0}")]
    Pack(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    pub server_addr: String,
    pub server_static_pub_hex: String,
    pub mask_profile: String,
    pub socks_listen: Option<String>,
    #[serde(default)]
    pub pack_trust_pub_hex: Option<String>,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            server_addr: "127.0.0.1:9443".into(),
            server_static_pub_hex: String::new(),
            mask_profile: "tls13_stable".into(),
            socks_listen: Some("127.0.0.1:11080".into()),
            pack_trust_pub_hex: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreStatus {
    pub state: String,
    pub mask: String,
    pub pack_id: Option<String>,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

pub struct CoreHandle {
    inner: Mutex<CoreInner>,
}

struct CoreInner {
    config: CoreConfig,
    pack: Option<MaskPack>,
    status: CoreStatus,
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// UniFFI: `core_start(config_json) -> handle`
pub fn core_start(config_json: &str) -> Result<CoreHandle, CoreError> {
    let config: CoreConfig =
        serde_json::from_str(config_json).map_err(|e| CoreError::Msg(e.to_string()))?;
    let mask = config.mask_profile.clone();
    Ok(CoreHandle {
        inner: Mutex::new(CoreInner {
            config,
            pack: None,
            status: CoreStatus {
                state: "started".into(),
                mask,
                pack_id: None,
                bytes_up: 0,
                bytes_down: 0,
            },
        }),
    })
}

pub fn core_stop(handle: CoreHandle) {
    if let Ok(mut g) = handle.inner.lock() {
        g.status.state = "stopped".into();
    }
}

/// UniFFI: `core_apply_mask_pack(handle, bytes) -> Result`
pub fn core_apply_mask_pack(handle: &CoreHandle, bytes: &[u8]) -> Result<(), CoreError> {
    let mut g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    let trust_hex = g
        .config
        .pack_trust_pub_hex
        .clone()
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
    if let Some(p) = pack.profiles.first() {
        g.status.mask = p.id.clone();
        g.config.mask_profile = p.id.clone();
    }
    g.pack = Some(pack);
    g.status.state = "pack_applied".into();
    Ok(())
}

pub fn core_status(handle: &CoreHandle) -> Result<String, CoreError> {
    let g = handle
        .inner
        .lock()
        .map_err(|_| CoreError::Msg("lock".into()))?;
    serde_json::to_string(&g.status).map_err(|e| CoreError::Msg(e.to_string()))
}

pub fn core_version() -> String {
    version().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swif_crypto::PackSigningKey;
    use swif_mask::sign_pack_value;

    #[test]
    fn uniffi_smoke_start_apply_status() {
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

        let cfg = CoreConfig {
            pack_trust_pub_hex: Some(hex::encode(vk.to_bytes())),
            ..CoreConfig::default()
        };
        let h = core_start(&serde_json::to_string(&cfg).unwrap()).unwrap();
        core_apply_mask_pack(&h, &bytes).unwrap();
        let st = core_status(&h).unwrap();
        assert!(st.contains("smoke"));
        assert!(st.contains("tls13_stable"));
        assert_eq!(core_version(), version());
        core_stop(h);
    }
}
