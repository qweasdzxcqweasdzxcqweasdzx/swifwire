use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use swif_wire::{encode_varint_u32, RecordHdr};

use crate::error::{Error, Result};

pub const TAG_LEN: usize = 16;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AeadKey(pub [u8; 32]);

#[derive(Clone, Copy, Default)]
pub struct NonceSalt(pub [u8; 4]);

impl Zeroize for NonceSalt {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

fn nonce_bytes(salt: NonceSalt, counter: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&salt.0);
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    Nonce::from(n)
}

/// Seal plaintext frame(+pad) into AEAD record bytes: hdr || len || ct||tag
pub fn seal_record(
    key: &AeadKey,
    salt: NonceSalt,
    counter: u64,
    hdr: RecordHdr,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    if counter == u64::MAX {
        return Err(Error::CounterOverflow);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).expect("key len");
    let hdr_b = hdr.encode();
    let mut len_buf = Vec::new();
    encode_varint_u32(plaintext.len() as u32, &mut len_buf);
    let mut aad = Vec::with_capacity(1 + len_buf.len());
    aad.push(hdr_b);
    aad.extend_from_slice(&len_buf);

    let ct = cipher
        .encrypt(
            &nonce_bytes(salt, counter),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Aead)?;

    let mut out = Vec::with_capacity(1 + len_buf.len() + ct.len());
    out.push(hdr_b);
    out.extend_from_slice(&len_buf);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Returns (plaintext, bytes_consumed_from_input)
pub fn open_record(
    key: &AeadKey,
    salt: NonceSalt,
    counter: u64,
    input: &[u8],
) -> Result<(RecordHdr, Vec<u8>, usize)> {
    if input.is_empty() {
        return Err(Error::BufferTooShort);
    }
    let hdr = RecordHdr::decode(input[0]);
    let (plen, vn) = swif_wire::decode_varint_u32(&input[1..])?;
    let start = 1 + vn;
    let ct_len = plen as usize + TAG_LEN;
    let end = start
        .checked_add(ct_len)
        .ok_or(Error::BufferTooShort)?;
    if end > input.len() {
        return Err(Error::BufferTooShort);
    }
    let mut len_buf = Vec::new();
    encode_varint_u32(plen, &mut len_buf);
    let mut aad = Vec::with_capacity(1 + len_buf.len());
    aad.push(input[0]);
    aad.extend_from_slice(&len_buf);

    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).expect("key len");
    let pt = cipher
        .decrypt(
            &nonce_bytes(salt, counter),
            Payload {
                msg: &input[start..end],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Aead)?;
    Ok((hdr, pt, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use swif_wire::RecordHdr;

    #[test]
    fn seal_open_roundtrip() {
        let key = AeadKey([7u8; 32]);
        let salt = NonceSalt([1, 2, 3, 4]);
        let sealed = seal_record(&key, salt, 0, RecordHdr::v0(), b"hello-frame").unwrap();
        let (_h, pt, n) = open_record(&key, salt, 0, &sealed).unwrap();
        assert_eq!(pt, b"hello-frame");
        assert_eq!(n, sealed.len());
    }
}
