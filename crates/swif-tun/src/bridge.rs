//! Pump TUN ↔ SwifWire DATAGRAM frames (assoc = TUN_ASSOC).

use crate::{packet_to_datagram_payload, TunDevice, TUN_ASSOC};
use swif_mux::Mux;

pub fn tun_to_frame(packet: &[u8]) -> swif_wire::Frame {
    Mux::datagram_frame(TUN_ASSOC, &packet_to_datagram_payload(packet))
}

pub async fn frame_to_tun(tun: &dyn TunDevice, frame: &swif_wire::Frame) -> crate::Result<()> {
    let (id, payload) = Mux::parse_datagram(frame).map_err(|e| crate::Error::Io(e.to_string()))?;
    if id != TUN_ASSOC {
        return Ok(());
    }
    tun.write_packet(&payload).await
}

pub async fn read_tun_frame(tun: &dyn TunDevice, buf: &mut [u8]) -> crate::Result<swif_wire::Frame> {
    let n = tun.read_packet(buf).await?;
    Ok(tun_to_frame(&buf[..n]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NullTun;

    #[tokio::test]
    async fn bridge_null_tun() {
        let tun = NullTun::new(1500);
        tun.inject_from_stack(&[0x60, 0, 0, 0]).await.unwrap();
        let mut buf = [0u8; 1500];
        let f = read_tun_frame(tun.as_ref(), &mut buf).await.unwrap();
        let tun2 = NullTun::new(1500);
        frame_to_tun(tun2.as_ref(), &f).await.unwrap();
        assert_eq!(tun2.drain_to_stack().await[0], vec![0x60, 0, 0, 0]);
        let _ = tun;
    }
}
