use swif_crypto::{open_record, seal_record, SessionKeys};
use swif_shape::Shaper;
use swif_wire::{Frame, RecordHdr};

use crate::error::Result;

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
}

impl SessionTransport {
    pub fn new_client(keys: SessionKeys, shaper: Shaper) -> Self {
        Self {
            keys,
            send_counter: 0,
            recv_counter: 0,
            is_client: true,
            shaper,
        }
    }

    pub fn new_server(keys: SessionKeys, shaper: Shaper) -> Self {
        Self {
            keys,
            send_counter: 0,
            recv_counter: 0,
            is_client: false,
            shaper,
        }
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

    pub fn seal_frame(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        let encoded = frame.encode_vec();
        let shaped = self.shaper.wrap(&encoded);
        let (key, salt) = self.send_key_salt();
        let out = seal_record(key, salt, self.send_counter, RecordHdr::v0(), &shaped)?;
        self.send_counter += 1;
        Ok(out)
    }

    pub fn seal_raw(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let shaped = self.shaper.wrap(plaintext);
        let (key, salt) = self.send_key_salt();
        let out = seal_record(key, salt, self.send_counter, RecordHdr::v0(), &shaped)?;
        self.send_counter += 1;
        Ok(out)
    }

    /// Decrypt one record from front of buffer; returns frame + pad leftover ignored.
    pub fn open_frame(&mut self, input: &[u8]) -> Result<(Frame, usize)> {
        let (key, salt) = self.recv_key_salt();
        let (_hdr, pt, n) = open_record(key, salt, self.recv_counter, input)?;
        self.recv_counter += 1;
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
}
