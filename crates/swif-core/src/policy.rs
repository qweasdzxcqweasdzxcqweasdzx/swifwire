//! Dial / mask fallback policy (client).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskId {
    Tls13Stable,
    /// Quinn QUIC + pref stream (lab until pack Initial mimicry).
    QuicStable,
    /// Thin UDP lab cover — not a prod fallback target.
    QuicLab,
    NullTcp,
}

impl MaskId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls13Stable => "tls13_stable",
            Self::QuicStable => "quic_stable",
            Self::QuicLab => "quic_lab",
            Self::NullTcp => "null_tcp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tls13_stable" => Some(Self::Tls13Stable),
            "quic_stable" => Some(Self::QuicStable),
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
    /// Prefer quic_stable over quic_lab when TLS dials exhaust (lab).
    pub allow_quic_stable_fallback: bool,
    /// Phase-1 dual-stack: opaque legacy share (not executed by SwifWire).
    pub legacy_fallback_uri: Option<String>,
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
            allow_quic_stable_fallback: std::env::var("SWIF_ALLOW_QUIC_STABLE").ok().as_deref()
                == Some("1")
                || std::env::var("SWIF_LAB").ok().as_deref() == Some("1"),
            legacy_fallback_uri: None,
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
            if self.preferred == MaskId::Tls13Stable {
                if self.allow_quic_stable_fallback {
                    self.preferred = MaskId::QuicStable;
                } else if self.allow_quic_lab_fallback {
                    self.preferred = MaskId::QuicLab;
                } else {
                    self.preferred = MaskId::Tls13Stable;
                }
            } else {
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
            if m == MaskId::QuicStable && !self.allow_quic_stable_fallback {
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

    /// After repeated timeouts, surface legacy URI for the host app (VPN UI dual-stack).
    pub fn legacy_hint_if_exhausted(&self) -> Option<&str> {
        if self.timeouts == 0 && self.backoff_ms > 0 {
            // just exhausted a switch cycle
        }
        if self.backoff_ms >= 150 * self.switch_after {
            return self.legacy_fallback_uri.as_deref();
        }
        None
    }

    pub fn set_legacy_fallback(&mut self, uri: Option<String>) {
        self.legacy_fallback_uri = uri;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(lab: bool, stable: bool) -> DialPolicy {
        DialPolicy {
            preferred: MaskId::Tls13Stable,
            timeouts: 0,
            switch_after: 3,
            backoff_ms: 0,
            allow_quic_lab_fallback: lab,
            allow_quic_stable_fallback: stable,
            legacy_fallback_uri: None,
        }
    }

    #[test]
    fn stays_on_tls_without_quic_lab_flag() {
        // Explicit flags — do not inherit SWIF_ALLOW_* from prod-gate env.
        let mut p = policy(false, false);
        assert_eq!(p.preferred, MaskId::Tls13Stable);
        p.on_handshake_timeout();
        p.on_handshake_timeout();
        let (next, backoff) = p.on_handshake_timeout();
        assert_eq!(next, MaskId::Tls13Stable);
        assert!(backoff > 0);
    }

    #[test]
    fn can_switch_to_quic_lab_when_allowed() {
        let mut p = policy(true, false);
        p.on_handshake_timeout();
        p.on_handshake_timeout();
        let (next, _) = p.on_handshake_timeout();
        assert_eq!(next, MaskId::QuicLab);
    }

    #[test]
    fn prefers_quic_stable_over_lab() {
        let mut p = policy(true, true);
        p.on_handshake_timeout();
        p.on_handshake_timeout();
        let (next, _) = p.on_handshake_timeout();
        assert_eq!(next, MaskId::QuicStable);
    }

    #[test]
    fn mask_offer_quic_ignored_without_flag() {
        let mut p = policy(false, false);
        p.on_mask_offer("quic_fast");
        assert_eq!(p.preferred, MaskId::Tls13Stable);
        p.on_mask_offer("quic_stable");
        assert_eq!(p.preferred, MaskId::Tls13Stable);
    }
}
