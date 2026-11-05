//! Session tickets for 0-RTT-ish resume (CONTROL / reconnect; no TUN in 0-RTT).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;

use crate::error::{Error, Result};

const NONCE_LEN: usize = 12;
const SECRET_LEN: usize = 32;
const EXPIRY_LEN: usize = 8;
const PLAIN_LEN: usize = SECRET_LEN + EXPIRY_LEN;

/// Seal `secret || expiry_unix` under ticket master key. Wire: nonce || ciphertext||tag.
pub fn seal_ticket(master: &[u8; 32], secret: &[u8; 32], expires_at_unix: u64) -> Result<Vec<u8>> {
    let mut plain = [0u8; PLAIN_LEN];
    plain[..SECRET_LEN].copy_from_slice(secret);
    plain[SECRET_LEN..].copy_from_slice(&expires_at_unix.to_be_bytes());

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(master).expect("key len");
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|_| Error::Aead)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open ticket → (secret, expires_at_unix).
pub fn open_ticket(master: &[u8; 32], blob: &[u8]) -> Result<([u8; 32], u64)> {
    if blob.len() < NONCE_LEN + PLAIN_LEN + 16 {
        return Err(Error::BufferTooShort);
    }
    let nonce = Nonce::from_slice(&blob[..NONCE_LEN]);
    let cipher = ChaCha20Poly1305::new_from_slice(master).expect("key len");
    let pt = cipher
        .decrypt(nonce, &blob[NONCE_LEN..])
        .map_err(|_| Error::Aead)?;
    if pt.len() != PLAIN_LEN {
        return Err(Error::Aead);
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&pt[..SECRET_LEN]);
    let expires = u64::from_be_bytes(pt[SECRET_LEN..].try_into().unwrap());
    Ok((secret, expires))
}

pub fn ticket_expired(expires_at_unix: u64, now_unix: u64) -> bool {
    now_unix > expires_at_unix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_roundtrip() {
        let master = [9u8; 32];
        let secret = [3u8; 32];
        let sealed = seal_ticket(&master, &secret, 1_900_000_000).unwrap();
        let (s2, exp) = open_ticket(&master, &sealed).unwrap();
        assert_eq!(s2, secret);
        assert_eq!(exp, 1_900_000_000);
        assert!(!ticket_expired(exp, 1_800_000_000));
        assert!(ticket_expired(exp, 2_000_000_000));
    }
}
