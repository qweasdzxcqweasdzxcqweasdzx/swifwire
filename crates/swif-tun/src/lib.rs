//! TUN abstraction + UDP map helpers.

mod bridge;
mod os;
mod udp_map;

pub use bridge::{frame_to_tun, read_tun_frame, tun_to_frame};
pub use os::OsTun;
pub use udp_map::{decode_udp4, encode_udp4, encode_udp4_reply};

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("tun closed")]
    Closed,
    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[async_trait]
pub trait TunDevice: Send + Sync {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize>;
    async fn write_packet(&self, packet: &[u8]) -> Result<()>;
    fn mtu(&self) -> usize;
}

pub struct NullTun {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound: Mutex<Vec<Vec<u8>>>,
    mtu: usize,
}

impl NullTun {
    pub fn new(mtu: usize) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(64);
        Arc::new(Self {
            tx,
            rx: Mutex::new(rx),
            outbound: Mutex::new(Vec::new()),
            mtu,
        })
    }

    pub async fn inject_from_stack(self: &Arc<Self>, packet: &[u8]) -> Result<()> {
        self.tx
            .send(packet.to_vec())
            .await
            .map_err(|_| Error::Closed)
    }

    pub async fn drain_to_stack(self: &Arc<Self>) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.outbound.lock().await)
    }
}

#[async_trait]
impl TunDevice for NullTun {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        let pkt = self.rx.lock().await.recv().await.ok_or(Error::Closed)?;
        let n = pkt.len().min(buf.len());
        buf[..n].copy_from_slice(&pkt[..n]);
        Ok(n)
    }

    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        self.outbound.lock().await.push(packet.to_vec());
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}

pub const TUN_ASSOC: u32 = 1;

pub fn packet_to_datagram_payload(packet: &[u8]) -> Vec<u8> {
    packet.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use swif_mux::Mux;

    #[tokio::test]
    async fn null_tun_roundtrip() {
        let tun = NullTun::new(1500);
        tun.inject_from_stack(&[0x45, 0, 0, 20]).await.unwrap();
        let mut buf = [0u8; 1500];
        let n = tun.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x45, 0, 0, 20]);
        tun.write_packet(b"reply").await.unwrap();
        assert_eq!(tun.drain_to_stack().await[0], b"reply");
    }

    #[test]
    fn tun_packet_maps_to_datagram_frame() {
        let f = Mux::datagram_frame(TUN_ASSOC, &[0x45, 1, 2, 3]);
        let (id, payload) = Mux::parse_datagram(&f).unwrap();
        assert_eq!(id, TUN_ASSOC);
        assert_eq!(payload, vec![0x45, 1, 2, 3]);
    }
}
