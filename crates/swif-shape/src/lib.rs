//! Mandatory padding / traffic shaping API.

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{Duration, Instant};

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
    /// Minimum pad bytes appended on every wrap (anti fixed first-record).
    #[serde(default = "default_min_pad")]
    pub min_pad: usize,
}

fn default_min_pad() -> usize {
    16
}

impl Default for ShaperProfile {
    fn default() -> Self {
        Self::desktop()
    }
}

impl ShaperProfile {
    pub fn desktop() -> Self {
        Self {
            id: "desktop".into(),
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
            jitter_ms: 400,
            max_pad: 800,
            min_pad: 16,
        }
    }

    pub fn mobile_idle() -> Self {
        Self {
            id: "mobile_idle".into(),
            length_hist: vec![
                LengthBin {
                    bytes: 96,
                    weight: 2.0,
                },
                LengthBin {
                    bytes: 256,
                    weight: 3.0,
                },
                LengthBin {
                    bytes: 800,
                    weight: 2.0,
                },
            ],
            idle_ms: 45_000,
            jitter_ms: 2_500,
            max_pad: 400,
            min_pad: 24,
        }
    }
}

pub struct Shaper {
    profile: ShaperProfile,
    disabled: bool,
    last_activity: Instant,
}

impl Shaper {
    pub fn new(profile: ShaperProfile) -> Self {
        let disabled = env::var("SWIF_SHAPE")
            .map(|v| v == "off" || v == "0")
            .unwrap_or(false);
        Self {
            profile,
            disabled,
            last_activity: Instant::now(),
        }
    }

    pub fn profile_id(&self) -> &str {
        &self.profile.id
    }

    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Next idle cover delay = idle_ms ± jitter (never fixed period).
    pub fn next_idle_delay(&self) -> Duration {
        if self.disabled {
            return Duration::from_secs(3600);
        }
        let j = self.profile.jitter_ms.max(1);
        let delta = (rand::thread_rng().gen::<u64>() % (j * 2 + 1)) as i64 - j as i64;
        let ms = (self.profile.idle_ms as i64 + delta).max(500) as u64;
        Duration::from_millis(ms)
    }

    pub fn idle_due(&self) -> bool {
        !self.disabled && self.last_activity.elapsed() >= self.next_idle_delay()
    }

    /// Time until next possible idle check (for select timeouts).
    pub fn idle_timeout(&self) -> Duration {
        let elapsed = self.last_activity.elapsed();
        let target = self.next_idle_delay();
        target.saturating_sub(elapsed).max(Duration::from_millis(200))
    }

    /// Append random pad so total plaintext length matches sampled target (or +pad up to max).
    pub fn wrap(&self, plain: &[u8]) -> Vec<u8> {
        if self.disabled {
            return plain.to_vec();
        }
        let target = self.sample_length().max(plain.len() + self.profile.min_pad);
        let pad_len = (target - plain.len())
            .max(self.profile.min_pad)
            .min(self.profile.max_pad);
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
        let n = self
            .sample_length()
            .max(self.profile.min_pad)
            .min(self.profile.max_pad.max(16));
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
        assert!(out.len() >= 2 + 16);
        assert_eq!(&out[..2], b"hi");
    }

    #[test]
    fn first_record_size_varies() {
        let s = Shaper::new(ShaperProfile::desktop());
        let mut lens = std::collections::BTreeSet::new();
        for _ in 0..40 {
            lens.insert(s.wrap(b"x").len());
        }
        assert!(
            lens.len() >= 2,
            "expected length variance, got {:?}",
            lens
        );
    }

    #[test]
    fn idle_delay_has_jitter_band() {
        let s = Shaper::new(ShaperProfile::desktop());
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..20 {
            seen.insert(s.next_idle_delay().as_millis());
        }
        assert!(seen.len() >= 2);
    }
}
