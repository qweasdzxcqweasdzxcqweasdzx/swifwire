//! `quic_fast` / **`quic_lab`** — thin UDP long-header wrapper (lab only; not Chrome FP).
//! WP3 will introduce pack-driven `quic_stable`; do not use as prod DialPolicy default.

use std::net::SocketAddr;

use rand::RngCore;
use tokio::net::UdpSocket;

/// Fake QUIC long-header version (lab).
pub const COVER_VERSION: u32 = 0x0000_0001;
pub const DCID_LEN: usize = 8;

/// Build one UDP datagram: long-header-ish cover + payload.
pub fn wrap_payload(dcid: &[u8; DCID_LEN], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + 1 + DCID_LEN + 1 + payload.len());
    out.push(0xC0); // long header form + fixed bits
    out.extend_from_slice(&COVER_VERSION.to_be_bytes());
    out.push(DCID_LEN as u8);
    out.extend_from_slice(dcid);
    out.push(0); // scid len = 0
    out.extend_from_slice(payload);
    out
}

/// Parse cover → (dcid, payload). Returns None if not our cover shape.
pub fn unwrap_payload(pkt: &[u8]) -> Option<([u8; DCID_LEN], &[u8])> {
    if pkt.len() < 1 + 4 + 1 + DCID_LEN + 1 {
        return None;
    }
    if pkt[0] & 0xC0 != 0xC0 {
        return None;
    }
    let ver = u32::from_be_bytes(pkt[1..5].try_into().ok()?);
    if ver != COVER_VERSION {
        return None;
    }
    if pkt[5] as usize != DCID_LEN {
        return None;
    }
    let mut dcid = [0u8; DCID_LEN];
    dcid.copy_from_slice(&pkt[6..6 + DCID_LEN]);
    let scid_len = pkt[6 + DCID_LEN] as usize;
    let start = 6 + DCID_LEN + 1 + scid_len;
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

/// Length-prefixed message over one UDP datagram (MVP: one pref msg = one datagram).
pub fn encode_pref_datagram(dcid: &[u8; DCID_LEN], msg: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(4 + msg.len());
    inner.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    inner.extend_from_slice(msg);
    wrap_payload(dcid, &inner)
}

pub fn decode_pref_datagram(pkt: &[u8]) -> Option<([u8; DCID_LEN], Vec<u8>)> {
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
    pub dcid: [u8; DCID_LEN],
}

impl QuicFastClient {
    pub async fn dial(peer: SocketAddr) -> std::io::Result<Self> {
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(peer).await?;
        Ok(Self {
            sock,
            peer,
            dcid: random_dcid(),
        })
    }

    pub async fn send_pref(&self, msg: &[u8]) -> std::io::Result<()> {
        let pkt = encode_pref_datagram(&self.dcid, msg);
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
        let id = random_dcid();
        let pkt = encode_pref_datagram(&id, b"hello-swif");
        let (id2, msg) = decode_pref_datagram(&pkt).unwrap();
        assert_eq!(id, id2);
        assert_eq!(msg, b"hello-swif");
    }
}
