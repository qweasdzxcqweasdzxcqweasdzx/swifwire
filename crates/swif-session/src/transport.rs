use swif_crypto::{derive_rekey_keys, open_record, seal_record, SessionKeys};
use swif_shape::Shaper;
use swif_wire::{Frame, RecordHdr, HDR_KEY_PHASE};

use crate::error::{Error, Result};

#[derive(Clone, Copy)]
pub enum Direction {
    C2s,
    S2c,
}

pub struct SessionTransport {
    keys: SessionKeys,
    send_counter: u64,
    recv_counter: u64,
    /// Am I the client? then send uses k_c2s
    is_client: bool,
    shaper: Shaper,
    /// Traffic secret epoch (0 = post-handshake).
    epoch: u64,
    /// Wire key_phase bit for AEAD records after odd epochs.
    key_phase: bool,
}

impl SessionTransport {
    pub fn new_client(keys: SessionKeys, shaper: Shaper) -> Self {
        Self {
            keys,
            send_counter: 0,
            recv_counter: 0,
            is_client: true,
            shaper,
            epoch: 0,
            key_phase: false,
        }
    }

    pub fn new_server(keys: SessionKeys, shaper: Shaper) -> Self {
        Self {
            keys,
            send_counter: 0,
            recv_counter: 0,
            is_client: false,
            shaper,
            epoch: 0,
            key_phase: false,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn send_key_salt(&self) -> (&swif_crypto::AeadKey, swif_crypto::NonceSalt) {
        if self.is_client {
            (&self.keys.k_c2s, self.keys.nonce_salt_c2s)
        } else {
            (&self.keys.k_s2c, self.keys.nonce_salt_s2c)
        }
    }

    fn recv_key_salt(&self) -> (&swif_crypto::AeadKey, swif_crypto::NonceSalt) {
        if self.is_client {
            (&self.keys.k_s2c, self.keys.nonce_salt_s2c)
        } else {
            (&self.keys.k_c2s, self.keys.nonce_salt_c2s)
        }
    }

    fn record_hdr(&self) -> RecordHdr {
        RecordHdr::v0_key_phase(self.key_phase)
    }

    pub fn seal_frame(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        let encoded = frame.encode_vec();
        let shaped = self.shaper.wrap(&encoded);
        let (key, salt) = self.send_key_salt();
        let out = seal_record(key, salt, self.send_counter, self.record_hdr(), &shaped)?;
        self.send_counter += 1;
        self.shaper.mark_activity();
        Ok(out)
    }

    pub fn seal_raw(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let shaped = self.shaper.wrap(plaintext);
        let (key, salt) = self.send_key_salt();
        let out = seal_record(key, salt, self.send_counter, self.record_hdr(), &shaped)?;
        self.send_counter += 1;
        self.shaper.mark_activity();
        Ok(out)
    }

    /// Idle cover: Ping with shaped opaque body (no TUN/SOCKS payload).
    pub fn seal_idle_cover(&mut self) -> Result<Option<Vec<u8>>> {
        let Some(pad) = self.shaper.on_idle() else {
            return Ok(None);
        };
        let frame = swif_wire::bodies::ping(&pad);
        Ok(Some(self.seal_frame(&frame)?))
    }

    pub fn idle_timeout(&self) -> std::time::Duration {
        self.shaper.idle_timeout()
    }

    /// Initiate local rekey to `epoch` (must be current+1). Caller sends CONTROL Rekey first.
    pub fn advance_rekey(&mut self, epoch: u64) -> Result<()> {
        if epoch != self.epoch + 1 {
            return Err(Error::Handshake);
        }
        self.keys = derive_rekey_keys(&self.keys, epoch);
        self.epoch = epoch;
        self.key_phase = !self.key_phase;
        self.send_counter = 0;
        self.recv_counter = 0;
        Ok(())
    }

    /// Decrypt one record from front of buffer; returns frame + pad leftover ignored.
    pub fn open_frame(&mut self, input: &[u8]) -> Result<(Frame, usize)> {
        let (key, salt) = self.recv_key_salt();
        let (hdr, pt, n) = open_record(key, salt, self.recv_counter, input)?;
        // Peers may flip key_phase on rekey; tolerate either bit while counters match keys.
        let _ = hdr.flags.0 & HDR_KEY_PHASE;
        self.recv_counter += 1;
        self.shaper.mark_activity();
        let (frame, _) = Frame::decode_with_pad(&pt)?;
        Ok((frame, n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swif_crypto::StaticKeypair;
    use swif_shape::ShaperProfile;
    use swif_wire::bodies;
    use crate::handshake::{client_finish_keys, client_hello_inner, server_respond_keys};

    #[test]
    fn seal_open_across_handshake() {
        let server = StaticKeypair::generate();
        let (cr, eph) = client_hello_inner(server.public_bytes(), 1);
        let (sr, ks) = server_respond_keys(&server, &cr, 1).unwrap();
        let kc = client_finish_keys(server.public_bytes(), &eph, &cr, &sr).unwrap();
        let shaper = Shaper::new(ShaperProfile::default());
        let mut c = SessionTransport::new_client(kc, Shaper::new(ShaperProfile::default()));
        let mut s = SessionTransport::new_server(ks, shaper);
        let f = bodies::stream_data(1, b"ping");
        let wire = c.seal_frame(&f).unwrap();
        let (got, n) = s.open_frame(&wire).unwrap();
        assert_eq!(n, wire.len());
        assert_eq!(got, f);
    }

    #[test]
    fn rekey_both_sides() {
        let server = StaticKeypair::generate();
        let (cr, eph) = client_hello_inner(server.public_bytes(), 1);
        let (sr, ks) = server_respond_keys(&server, &cr, 1).unwrap();
        let kc = client_finish_keys(server.public_bytes(), &eph, &cr, &sr).unwrap();
        let mut c = SessionTransport::new_client(kc, Shaper::new(ShaperProfile::default()));
        let mut s = SessionTransport::new_server(ks, Shaper::new(ShaperProfile::default()));
        c.advance_rekey(1).unwrap();
        s.advance_rekey(1).unwrap();
        let f = bodies::stream_data(1, b"after-rekey");
        let wire = c.seal_frame(&f).unwrap();
        let (got, _) = s.open_frame(&wire).unwrap();
        assert_eq!(got, f);
    }

    #[test]
    fn rekey_control_ack_under_old_keys() {
        let server = StaticKeypair::generate();
        let (cr, eph) = client_hello_inner(server.public_bytes(), 1);
        let (sr, ks) = server_respond_keys(&server, &cr, 1).unwrap();
        let kc = client_finish_keys(server.public_bytes(), &eph, &cr, &sr).unwrap();
        let mut c = SessionTransport::new_client(kc, Shaper::new(ShaperProfile::default()));
        let mut s = SessionTransport::new_server(ks, Shaper::new(ShaperProfile::default()));

        let epoch = 1u64;
        let offer = c.seal_frame(&swif_wire::rekey(epoch)).unwrap();
        let (of, _) = s.open_frame(&offer).unwrap();
        let (ty, p) = swif_wire::parse_ctrl(&of).unwrap();
        assert_eq!(ty, swif_wire::CtrlType::Rekey);
        assert_eq!(swif_wire::parse_rekey(&p), Some(epoch));
        assert_eq!(epoch, s.epoch() + 1);

        let ack = s.seal_frame(&swif_wire::rekey(epoch)).unwrap();
        s.advance_rekey(epoch).unwrap();

        let (af, _) = c.open_frame(&ack).unwrap();
        let (ty2, p2) = swif_wire::parse_ctrl(&af).unwrap();
        assert_eq!(ty2, swif_wire::CtrlType::Rekey);
        assert_eq!(swif_wire::parse_rekey(&p2), Some(epoch));
        c.advance_rekey(epoch).unwrap();

        let f = bodies::stream_data(1, b"post");
        let wire = c.seal_frame(&f).unwrap();
        let (got, _) = s.open_frame(&wire).unwrap();
        assert_eq!(got, f);
    }
}
