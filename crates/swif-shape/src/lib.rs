//! Mandatory padding / traffic shaping API.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LengthBin {
    pub bytes: usize,
    pub weight: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShaperProfile {
    pub id: String,
    pub length_hist: Vec<LengthBin>,
    pub idle_ms: u64,
    pub jitter_ms: u64,
    pub max_pad: usize,
}

impl Default for ShaperProfile {
    fn default() -> Self {
        Self {
            id: "default".into(),
            length_hist: vec![
                LengthBin {
                    bytes: 64,
                    weight: 1.0,
                },
                LengthBin {
                    bytes: 512,
                    weight: 3.0,
                },
                LengthBin {
                    bytes: 1200,
                    weight: 5.0,
                },
                LengthBin {
                    bytes: 1400,
                    weight: 2.0,
                },
            ],
            idle_ms: 15_000,
            jitter_ms: 40,
            max_pad: 800,
        }
    }
}

pub struct Shaper {
    profile: ShaperProfile,
    disabled: bool,
}

impl Shaper {
    pub fn new(profile: ShaperProfile) -> Self {
        let disabled = env::var("SWIF_SHAPE")
            .map(|v| v == "off" || v == "0")
            .unwrap_or(false);
        Self { profile, disabled }
    }

    pub fn profile_id(&self) -> &str {
        &self.profile.id
    }

    /// Append random pad so total plaintext length matches sampled target (or +pad up to max).
    pub fn wrap(&self, plain: &[u8]) -> Vec<u8> {
        if self.disabled {
            return plain.to_vec();
        }
        let target = self.sample_length().max(plain.len());
        let pad_len = (target - plain.len()).min(self.profile.max_pad);
        let mut out = Vec::with_capacity(plain.len() + pad_len);
        out.extend_from_slice(plain);
        if pad_len > 0 {
            let mut pad = vec![0u8; pad_len];
            rand::thread_rng().fill(&mut pad[..]);
            out.extend_from_slice(&pad);
        }
        out
    }

    /// Optional cover frame body when idle (empty = skip).
    pub fn on_idle(&self) -> Option<Vec<u8>> {
        if self.disabled {
            return None;
        }
        let n = self.sample_length().min(self.profile.max_pad.max(16));
        let mut pad = vec![0u8; n];
        rand::thread_rng().fill(&mut pad[..]);
        Some(pad)
    }

    fn sample_length(&self) -> usize {
        let hist = &self.profile.length_hist;
        if hist.is_empty() {
            return 512;
        }
        let total: f64 = hist.iter().map(|b| b.weight).sum();
        let mut r: f64 = rand::thread_rng().gen::<f64>() * total;
        for b in hist {
            r -= b.weight;
            if r <= 0.0 {
                return b.bytes;
            }
        }
        hist.last().map(|b| b.bytes).unwrap_or(512)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_grows_or_equal() {
        let s = Shaper::new(ShaperProfile::default());
        let out = s.wrap(b"hi");
        assert!(out.len() >= 2);
        assert_eq!(&out[..2], b"hi");
    }
}
