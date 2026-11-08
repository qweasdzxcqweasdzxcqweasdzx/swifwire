use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::{AeadKey, NonceSalt};

pub const LABEL_C2S: &str = "swifwire/v0/key_c2s";
pub const LABEL_S2C: &str = "swifwire/v0/key_s2c";
pub const LABEL_TICKET: &str = "swifwire/v0/ticket";
pub const LABEL_NONCE: &str = "swifwire/v0/nonce_salt";
pub const LABEL_PAD: &str = "swifwire/v0/padseed";
pub const LABEL_REKEY: &str = "swifwire/v0/rekey";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub k_c2s: AeadKey,
    pub k_s2c: AeadKey,
    pub k_ticket: [u8; 32],
    pub nonce_salt_c2s: NonceSalt,
    pub nonce_salt_s2c: NonceSalt,
    pub pad_seed: [u8; 32],
}

fn expand(prk_ikm: &[u8], salt: &[u8], info: &str, out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), prk_ikm);
    hk.expand(info.as_bytes(), out)
        .expect("hkdf expand len ok");
}

/// `shared` = Noise/X25519 shared secret; `transcript` = hash of handshake messages.
pub fn derive_session_keys(shared: &[u8], transcript: &[u8]) -> SessionKeys {
    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    let mut k_ticket = [0u8; 32];
    let mut ns_c = [0u8; 4];
    let mut ns_s = [0u8; 4];
    let mut pad = [0u8; 32];

    expand(shared, transcript, LABEL_C2S, &mut k_c2s);
    expand(shared, transcript, LABEL_S2C, &mut k_s2c);
    expand(shared, transcript, LABEL_TICKET, &mut k_ticket);
    expand(shared, transcript, &(LABEL_NONCE.to_string() + "/c2s"), &mut ns_c);
    expand(shared, transcript, &(LABEL_NONCE.to_string() + "/s2c"), &mut ns_s);
    expand(shared, transcript, LABEL_PAD, &mut pad);

    SessionKeys {
        k_c2s: AeadKey(k_c2s),
        k_s2c: AeadKey(k_s2c),
        k_ticket,
        nonce_salt_c2s: NonceSalt(ns_c),
        nonce_salt_s2c: NonceSalt(ns_s),
        pad_seed: pad,
    }
}

/// Derive next epoch keys from current traffic secrets + epoch counter (SwifHS rekey).
pub fn derive_rekey_keys(current: &SessionKeys, epoch: u64) -> SessionKeys {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(&current.k_c2s.0);
    ikm[32..].copy_from_slice(&current.k_s2c.0);
    let mut salt = [0u8; 16];
    salt[..8].copy_from_slice(&epoch.to_be_bytes());
    salt[8..].copy_from_slice(LABEL_REKEY.as_bytes().get(..8).unwrap_or(b"rekeyv0!"));
    derive_session_keys(&ikm, &salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_directional() {
        let a = derive_session_keys(b"shared-secret-32-bytes-pad!!!!!!", b"transcript");
        let b = derive_session_keys(b"shared-secret-32-bytes-pad!!!!!!", b"transcript");
        assert_eq!(a.k_c2s.0, b.k_c2s.0);
        assert_ne!(a.k_c2s.0, a.k_s2c.0);
    }

    #[test]
    fn rekey_changes_keys() {
        let a = derive_session_keys(b"shared-secret-32-bytes-pad!!!!!!", b"transcript");
        let b = derive_rekey_keys(&a, 1);
        let c = derive_rekey_keys(&a, 1);
        assert_ne!(a.k_c2s.0, b.k_c2s.0);
        assert_eq!(b.k_c2s.0, c.k_c2s.0);
        assert_ne!(derive_rekey_keys(&a, 2).k_c2s.0, b.k_c2s.0);
    }
}
