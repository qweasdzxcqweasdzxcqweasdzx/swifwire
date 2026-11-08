//! `quic_fast` / **`quic_lab`** — thin UDP long-header cover (lab only).
//!
//! WP3: grease DCID/version randomization. Pack [`QuicInitialTemplate`] can
//! override grease pool + SCID len. Full `quic_stable` (quinn) — see `quic_stable.rs`.

use std::net::SocketAddr;

use rand::RngCore;
use tokio::net::UdpSocket;

use crate::quic_initial::QuicInitialTemplate;

/// Legacy fixed version (still accepted on unwrap for old peers).
pub const COVER_VERSION: u32 = 0x0000_0001;
pub const DCID_LEN: usize = 8;

fn grease_version_with(tmpl: Option<&QuicInitialTemplate>) -> u32 {
    if let Some(t) = tmpl {
        return t.pick_grease_version();
    }
    // Mix fixed lab version with grease-like values (low entropy, not Chrome FP).
    const CANDIDATES: [u32; 5] = [
        COVER_VERSION,
        0x6b33_1efd, // classic QUIC grease pattern-ish
        0x0000_0001,
        0xface_b001,
        0x0a0a_0a0a,
    ];
    let i = (rand::random::<u8>() as usize) % CANDIDATES.len();
    CANDIDATES[i]
}

/// Build one UDP datagram: long-header-ish cover + payload (variable DCID 4..=16).
pub fn wrap_payload(dcid: &[u8], payload: &[u8]) -> Vec<u8> {
    wrap_payload_with(dcid, payload, None)
}

/// Like [`wrap_payload`], applying pack Initial template grease / SCID len.
pub fn wrap_payload_with(
    dcid: &[u8],
    payload: &[u8],
    tmpl: Option<&QuicInitialTemplate>,
) -> Vec<u8> {
    let dcid_len = dcid.len().clamp(4, 20);
    let scid_len = tmpl.map(|t| t.scid_len.min(20) as usize).unwrap_or(0);
    let pad = tmpl.map(|t| t.pad_hint as usize).unwrap_or(0);
    let mut out =
        Vec::with_capacity(1 + 4 + 1 + dcid_len + 1 + scid_len + payload.len() + pad);
    let form = 0xC0u8 | (rand::random::<u8>() & 0x0F); // long header + grease low bits
    out.push(form);
    out.extend_from_slice(&grease_version_with(tmpl).to_be_bytes());
    out.push(dcid_len as u8);
    out.extend_from_slice(&dcid[..dcid_len]);
    out.push(scid_len as u8);
    if scid_len > 0 {
        let mut scid = vec![0u8; scid_len];
        rand::thread_rng().fill_bytes(&mut scid);
        out.extend_from_slice(&scid);
    }
    out.extend_from_slice(payload);
    if pad > 0 {
        let mut p = vec![0u8; pad];
        rand::thread_rng().fill_bytes(&mut p);
        out.extend_from_slice(&p);
    }
    out
}

/// Parse cover → (dcid, payload). Accepts variable DCID and any long-header version.
pub fn unwrap_payload(pkt: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    if pkt.len() < 1 + 4 + 1 + 4 + 1 {
        return None;
    }
    if pkt[0] & 0x80 == 0 {
        return None; // require long-header form bit
    }
    let dcid_len = pkt[5] as usize;
    if !(4..=20).contains(&dcid_len) {
        return None;
    }
    if pkt.len() < 6 + dcid_len + 1 {
        return None;
    }
    let dcid = pkt[6..6 + dcid_len].to_vec();
    let scid_len = pkt[6 + dcid_len] as usize;
    let start = 6 + dcid_len + 1 + scid_len;
    if start > pkt.len() {
        return None;
    }
    Some((dcid, &pkt[start..]))
}

pub fn random_dcid() -> [u8; DCID_LEN] {
    let mut id = [0u8; DCID_LEN];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

pub fn random_dcid_var() -> Vec<u8> {
    let n = 4 + (rand::random::<usize>() % 13); // 4..16
    let mut id = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Length-prefixed message over one UDP datagram (MVP: one pref msg = one datagram).
pub fn encode_pref_datagram(dcid: &[u8; DCID_LEN], msg: &[u8]) -> Vec<u8> {
    encode_pref_datagram_slice(dcid, msg)
}

pub fn encode_pref_datagram_slice(dcid: &[u8], msg: &[u8]) -> Vec<u8> {
    encode_pref_datagram_slice_with(dcid, msg, None)
}

pub fn encode_pref_datagram_slice_with(
    dcid: &[u8],
    msg: &[u8],
    tmpl: Option<&QuicInitialTemplate>,
) -> Vec<u8> {
    let mut inner = Vec::with_capacity(4 + msg.len());
    inner.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    inner.extend_from_slice(msg);
    wrap_payload_with(dcid, &inner, tmpl)
}

pub fn decode_pref_datagram(pkt: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (dcid, inner) = unwrap_payload(pkt)?;
    if inner.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes(inner[0..4].try_into().ok()?) as usize;
    if inner.len() < 4 + n {
        return None;
    }
    Some((dcid, inner[4..4 + n].to_vec()))
}

pub struct QuicFastClient {
    pub sock: UdpSocket,
    pub peer: SocketAddr,
    pub dcid: Vec<u8>,
}

impl QuicFastClient {
    pub async fn dial(peer: SocketAddr) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(peer).await?;
        Ok(Self {
            sock,
            peer,
            dcid: random_dcid_var(),
        })
    }

    pub async fn send_pref(&self, msg: &[u8]) -> std::io::Result<()> {
        let pkt = encode_pref_datagram_slice(&self.dcid, msg);
        self.sock.send(&pkt).await?;
        Ok(())
    }

    pub async fn recv_pref(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 64 * 1024];
        let n = self.sock.recv(&mut buf).await?;
        decode_pref_datagram(&buf[..n])
            .map(|(_, m)| m)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad quic cover"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip() {
        let id = random_dcid_var();
        let pkt = encode_pref_datagram_slice(&id, b"hello-swif");
        let (id2, msg) = decode_pref_datagram(&pkt).unwrap();
        assert_eq!(id, id2);
        assert_eq!(msg, b"hello-swif");
    }

    #[test]
    fn fixed_dcid_still_works() {
        let id = random_dcid();
        let pkt = encode_pref_datagram(&id, b"x");
        let (id2, msg) = decode_pref_datagram(&pkt).unwrap();
        assert_eq!(&id[..], &id2[..]);
        assert_eq!(msg, b"x");
    }

    #[test]
    fn pack_template_scid_and_pad() {
        let tmpl = QuicInitialTemplate {
            version: 1,
            dcid_len: 8,
            scid_len: 4,
            grease_versions: vec![0xface_b001],
            pad_hint: 16,
            has_opaque: false,
            opaque: vec![],
        };
        let id = tmpl.random_dcid();
        let pkt = encode_pref_datagram_slice_with(&id, b"hello", Some(&tmpl));
        let (id2, msg) = decode_pref_datagram(&pkt).unwrap();
        assert_eq!(id, id2);
        assert_eq!(msg, b"hello");
        // long-header + version + lens + dcid + scid + pref + pad
        assert!(pkt.len() > 1 + 4 + 1 + id.len() + 1 + 4 + 4 + 5);
    }
}
