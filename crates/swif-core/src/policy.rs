//! Dial / mask fallback policy (client).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskId {
    Tls13Stable,
    /// Thin UDP lab cover — not a prod fallback target.
    QuicLab,
    NullTcp,
}

impl MaskId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls13Stable => "tls13_stable",
            Self::QuicLab => "quic_lab",
            Self::NullTcp => "null_tcp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tls13_stable" => Some(Self::Tls13Stable),
            "quic_fast" | "quic_lab" => Some(Self::QuicLab),
            "null_tcp" => Some(Self::NullTcp),
            _ => None,
        }
    }

    pub fn is_prod_default_candidate(&self) -> bool {
        matches!(self, Self::Tls13Stable)
    }
}

#[derive(Debug, Clone)]
pub struct DialPolicy {
    pub preferred: MaskId,
    pub timeouts: u32,
    pub switch_after: u32,
    pub backoff_ms: u32,
    /// If false (default), never auto-switch to quic_lab.
    pub allow_quic_lab_fallback: bool,
}

impl Default for DialPolicy {
    fn default() -> Self {
        Self {
            preferred: MaskId::Tls13Stable,
            timeouts: 0,
            switch_after: 3,
            backoff_ms: 0,
            allow_quic_lab_fallback: std::env::var("SWIF_ALLOW_QUIC_LAB").ok().as_deref()
                == Some("1"),
        }
    }
}

impl DialPolicy {
    /// Record a dial/handshake timeout. Returns mask to try next + optional backoff ms.
    pub fn on_handshake_timeout(&mut self) -> (MaskId, u32) {
        self.timeouts = self.timeouts.saturating_add(1);
        let backoff = 150u32.saturating_mul(self.timeouts.min(8));
        self.backoff_ms = backoff;
        if self.timeouts >= self.switch_after {
            self.timeouts = 0;
            if self.allow_quic_lab_fallback && self.preferred == MaskId::Tls13Stable {
                self.preferred = MaskId::QuicLab;
            } else {
                // Stay on tls13_stable; increase backoff only (phase-1: no legacy wire).
                self.preferred = MaskId::Tls13Stable;
            }
        }
        (self.preferred.clone(), self.backoff_ms)
    }

    pub fn on_success(&mut self) {
        self.timeouts = 0;
        self.clear_backoff();
    }

    pub fn on_mask_offer(&mut self, profile: &str) {
        if let Some(m) = MaskId::parse(profile) {
            if m == MaskId::QuicLab && !self.allow_quic_lab_fallback {
                return;
            }
            self.preferred = m;
            self.timeouts = 0;
        }
    }

    pub fn on_backoff(&mut self, ms: u32) {
        self.backoff_ms = ms;
    }

    pub fn clear_backoff(&mut self) {
        self.backoff_ms = 0;
    }

    pub fn current(&self) -> &MaskId {
        &self.preferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stays_on_tls_without_quic_lab_flag() {
        let mut p = DialPolicy {
            allow_quic_lab_fallback: false,
            ..Default::default()
        };
        assert_eq!(p.preferred, MaskId::Tls13Stable);
        p.on_handshake_timeout();
        p.on_handshake_timeout();
        let (next, backoff) = p.on_handshake_timeout();
        assert_eq!(next, MaskId::Tls13Stable);
        assert!(backoff > 0);
    }

    #[test]
    fn can_switch_to_quic_lab_when_allowed() {
        let mut p = DialPolicy {
            allow_quic_lab_fallback: true,
            ..Default::default()
        };
        p.on_handshake_timeout();
        p.on_handshake_timeout();
        let (next, _) = p.on_handshake_timeout();
        assert_eq!(next, MaskId::QuicLab);
    }

    #[test]
    fn mask_offer_quic_ignored_without_flag() {
        let mut p = DialPolicy {
            allow_quic_lab_fallback: false,
            ..Default::default()
        };
        p.on_mask_offer("quic_fast");
        assert_eq!(p.preferred, MaskId::Tls13Stable);
    }
}
