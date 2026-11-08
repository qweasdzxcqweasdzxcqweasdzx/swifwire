//! `quic_stable` — pack-driven QUIC-like underlay (WP3).
//!
//! ## Target framing (normative intent)
//! 1. Real QUIC 1-RTT (quinn) with pack-selected ALPN (`h3` or cover ALPN).
//! 2. Bidirectional QUIC stream 0 carries length-prefixed SwifHS + AEAD records
//!    (same pref framing as TCP masks — see [`PrefStreamBuf`]).
//! 3. Datagrams map to QUIC datagrams when available.
//!
//! Status: **scaffold + stream framing bridge**. Runtime still uses greased `quic_lab`.
//! Do not select as DialPolicy prod default until `is_runtime_ready()` is true.

use crate::pack::MaskProfile;

pub const PROFILE_ID: &str = "quic_stable";

/// Max single pref record on a QUIC stream (matches TCP `read_pref`).
pub const MAX_PREF_RECORD: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QuicStableHints {
    pub alpn: Vec<String>,
    pub sni_pool_ref: Option<String>,
    pub has_initial_template: bool,
}

impl Default for QuicStableHints {
    fn default() -> Self {
        Self {
            alpn: vec!["h3".into()],
            sni_pool_ref: None,
            has_initial_template: false,
        }
    }
}

impl QuicStableHints {
    pub fn from_mask_profile(p: &MaskProfile) -> Self {
        let mut h = Self::default();
        if let Some(b64) = p
            .templates
            .get("quic_initial_b64")
            .and_then(|v| v.as_str())
        {
            h.has_initial_template = !b64.is_empty();
        }
        if let Some(cover) = &p.cover {
            if let Some(arr) = cover.get("alpn").and_then(|v| v.as_array()) {
                let list: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                if !list.is_empty() {
                    h.alpn = list;
                }
            }
            h.sni_pool_ref = cover
                .get("sni_pool_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
        h
    }
}

/// Encode one length-prefixed record for a reliable QUIC stream (stream 0).
pub fn encode_pref_record(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + msg.len());
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefStreamError {
    TooLarge,
}

impl std::fmt::Display for PrefStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "pref record too large"),
        }
    }
}

impl std::error::Error for PrefStreamError {}

/// Incremental decoder for length-prefixed records on an ordered byte stream.
///
/// Quinn/quiche stream reads are chunked; this buffer reassembles SwifWire
/// pref frames identically to TCP `read_pref` / `write_pref`.
#[derive(Debug, Default)]
pub struct PrefStreamBuf {
    buf: Vec<u8>,
}

impl PrefStreamBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Pop one complete record, or `Ok(None)` if more bytes are needed.
    pub fn pop_record(&mut self) -> Result<Option<Vec<u8>>, PrefStreamError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if n > MAX_PREF_RECORD {
            return Err(PrefStreamError::TooLarge);
        }
        if self.buf.len() < 4 + n {
            return Ok(None);
        }
        let msg = self.buf[4..4 + n].to_vec();
        self.buf.drain(..4 + n);
        Ok(Some(msg))
    }

    /// Drain all complete records currently buffered.
    pub fn pop_all(&mut self) -> Result<Vec<Vec<u8>>, PrefStreamError> {
        let mut out = Vec::new();
        while let Some(r) = self.pop_record()? {
            out.push(r);
        }
        Ok(out)
    }
}

/// True when a real QUIC stack + pack templates are wired (not yet).
pub fn is_runtime_ready() -> bool {
    false
}

/// Human-readable status for agents / CLIENT_SDK.
pub fn status_message() -> &'static str {
    "quic_stable: PrefStreamBuf framing ready; quinn dial/accept still scaffold (use quic_lab + SWIF_ALLOW_QUIC_LAB)"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn not_ready() {
        assert!(!is_runtime_ready());
        assert!(!status_message().is_empty());
    }

    #[test]
    fn parses_hints() {
        let p = MaskProfile {
            id: PROFILE_ID.into(),
            underlay: "udp".into(),
            default_port: Some(443),
            shaper: json!({}),
            templates: json!({"quic_initial_b64": "AAAA"}),
            cover: Some(json!({"alpn": ["h3"], "sni_pool_ref": "q.v1"})),
        };
        let h = QuicStableHints::from_mask_profile(&p);
        assert!(h.has_initial_template);
        assert_eq!(h.alpn, vec!["h3"]);
    }

    #[test]
    fn pref_stream_chunked_roundtrip() {
        let a = encode_pref_record(b"hello");
        let b = encode_pref_record(b"world-swif");
        let mut wire = Vec::new();
        wire.extend_from_slice(&a);
        wire.extend_from_slice(&b);

        let mut dec = PrefStreamBuf::new();
        // Feed in awkward chunk sizes (simulates QUIC stream reads).
        for chunk in wire.chunks(3) {
            dec.push(chunk);
        }
        let msgs = dec.pop_all().unwrap();
        assert_eq!(msgs, vec![b"hello".to_vec(), b"world-swif".to_vec()]);
        assert_eq!(dec.pending(), 0);
    }

    #[test]
    fn pref_stream_rejects_huge() {
        let mut dec = PrefStreamBuf::new();
        let n = (MAX_PREF_RECORD as u32).saturating_add(1).to_be_bytes();
        dec.push(&n);
        assert_eq!(dec.pop_record(), Err(PrefStreamError::TooLarge));
    }
}
