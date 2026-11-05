//! Dial / mask fallback policy (client).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskId {
    Tls13Stable,
    QuicFast,
    NullTcp,
}

impl MaskId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tls13Stable => "tls13_stable",
            Self::QuicFast => "quic_fast",
            Self::NullTcp => "null_tcp",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tls13_stable" => Some(Self::Tls13Stable),
            "quic_fast" => Some(Self::QuicFast),
            "null_tcp" => Some(Self::NullTcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DialPolicy {
    pub preferred: MaskId,
    pub timeouts: u32,
    pub switch_after: u32,
    pub backoff_ms: u32,
}

impl Default for DialPolicy {
    fn default() -> Self {
        Self {
            preferred: MaskId::Tls13Stable,
            timeouts: 0,
            switch_after: 3,
            backoff_ms: 0,
        }
    }
}

impl DialPolicy {
    pub fn on_handshake_timeout(&mut self) -> MaskId {
        self.timeouts = self.timeouts.saturating_add(1);
        if self.timeouts >= self.switch_after {
            self.timeouts = 0;
            self.preferred = match self.preferred {
                MaskId::Tls13Stable => MaskId::QuicFast,
                MaskId::QuicFast => MaskId::Tls13Stable,
                MaskId::NullTcp => MaskId::Tls13Stable,
            };
        }
        self.preferred.clone()
    }

    pub fn on_mask_offer(&mut self, profile: &str) {
        if let Some(m) = MaskId::parse(profile) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switches_after_three_timeouts() {
        let mut p = DialPolicy::default();
        assert_eq!(p.preferred, MaskId::Tls13Stable);
        p.on_handshake_timeout();
        p.on_handshake_timeout();
        assert_eq!(p.preferred, MaskId::Tls13Stable);
        let next = p.on_handshake_timeout();
        assert_eq!(next, MaskId::QuicFast);
        p.on_mask_offer("tls13_stable");
        assert_eq!(p.preferred, MaskId::Tls13Stable);
    }
}
