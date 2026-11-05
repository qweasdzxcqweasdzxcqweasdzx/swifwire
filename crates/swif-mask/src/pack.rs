//! Signed mask pack load / hot-apply (ed25519).

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use swif_crypto::{PackSigningKey, PackVerifyingKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PackError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing signature")]
    MissingSig,
    #[error("bad signature encoding")]
    BadSig,
    #[error("signature verify failed")]
    Verify,
    #[error("unsupported format")]
    Format,
    #[error("profile not found: {0}")]
    NoProfile(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskPack {
    pub format: u32,
    pub pack_id: String,
    pub min_core: String,
    #[serde(default)]
    pub issued_at: Option<String>,
    pub profiles: Vec<MaskProfile>,
    #[serde(default)]
    pub flags: serde_json::Map<String, Value>,
    pub signature: PackSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskProfile {
    pub id: String,
    pub underlay: String,
    #[serde(default)]
    pub default_port: Option<u16>,
    pub shaper: Value,
    #[serde(default)]
    pub templates: Value,
    #[serde(default)]
    pub cover: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackSignature {
    pub alg: String,
    pub key_id: String,
    pub sig_b64: String,
}

/// Canonical bytes to sign: JSON object without `signature` field, compact.
pub fn signing_bytes(raw: &Value) -> Result<Vec<u8>, PackError> {
    let mut obj = raw.as_object().cloned().ok_or(PackError::Format)?;
    obj.remove("signature");
    Ok(serde_json::to_vec(&Value::Object(obj))?)
}

pub fn sign_pack_value(mut raw: Value, sk: &PackSigningKey, key_id: &str) -> Result<Value, PackError> {
    let msg = signing_bytes(&raw)?;
    let sig = sk.sign(&msg);
    let b64 = base64::engine::general_purpose::STANDARD.encode(sig);
    if let Some(obj) = raw.as_object_mut() {
        obj.insert(
            "signature".into(),
            serde_json::json!({
                "alg": "ed25519",
                "key_id": key_id,
                "sig_b64": b64,
            }),
        );
    }
    Ok(raw)
}

pub fn verify_and_load(bytes: &[u8], trust: &PackVerifyingKey) -> Result<MaskPack, PackError> {
    let raw: Value = serde_json::from_slice(bytes)?;
    let msg = signing_bytes(&raw)?;
    let sig_b64 = raw
        .get("signature")
        .and_then(|s| s.get("sig_b64"))
        .and_then(|v| v.as_str())
        .ok_or(PackError::MissingSig)?;
    let sig_raw = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|_| PackError::BadSig)?;
    if sig_raw.len() != 64 {
        return Err(PackError::BadSig);
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_raw);
    trust.verify(&msg, &sig).map_err(|_| PackError::Verify)?;
    let pack: MaskPack = serde_json::from_value(raw)?;
    if pack.format != 1 {
        return Err(PackError::Format);
    }
    Ok(pack)
}

impl MaskPack {
    pub fn profile(&self, id: &str) -> Result<&MaskProfile, PackError> {
        self.profiles
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| PackError::NoProfile(id.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_pack() {
        let sk = PackSigningKey::generate();
        let vk = sk.verifying_key();
        let raw = serde_json::json!({
            "format": 1,
            "pack_id": "lab",
            "min_core": "0.1.0",
            "profiles": [{
                "id": "tls13_stable",
                "underlay": "tcp",
                "shaper": {"length_hist":[{"bytes":64,"weight":1}],"idle_ms":1000},
                "templates": {}
            }],
            "signature": {"alg":"ed25519","key_id":"x","sig_b64":"AA"}
        });
        let signed = sign_pack_value(raw, &sk, "dev").unwrap();
        let bytes = serde_json::to_vec(&signed).unwrap();
        let pack = verify_and_load(&bytes, &vk).unwrap();
        assert_eq!(pack.pack_id, "lab");
        assert!(pack.profile("tls13_stable").is_ok());
    }
}
