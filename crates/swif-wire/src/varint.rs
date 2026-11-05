//! Unsigned LEB128 varints (u32 max 5 bytes, u64 max 10).

use crate::error::{Error, Result};

pub fn encode_varint_u32(mut v: u32, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

pub fn encode_varint_u64(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

pub fn decode_varint_u32(input: &[u8]) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    for (i, &b) in input.iter().enumerate() {
        if i >= 5 {
            return Err(Error::VarintOverflow);
        }
        result |= u32::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift >= 32 {
            return Err(Error::VarintOverflow);
        }
    }
    Err(Error::BufferTooShort)
}

pub fn decode_varint_u64(input: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in input.iter().enumerate() {
        if i >= 10 {
            return Err(Error::VarintOverflow);
        }
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(Error::VarintOverflow);
        }
    }
    Err(Error::BufferTooShort)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_small() {
        for v in [0u32, 1, 127, 128, 255, 16384, u32::MAX] {
            let mut buf = Vec::new();
            encode_varint_u32(v, &mut buf);
            let (got, n) = decode_varint_u32(&buf).unwrap();
            assert_eq!(got, v);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn known_hex() {
        // 300 = 0x12C → LEB128: AC 02
        let mut buf = Vec::new();
        encode_varint_u32(300, &mut buf);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }
}
