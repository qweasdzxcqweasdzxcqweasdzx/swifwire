//! Frame and AEAD record header types.

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::varint::{decode_varint_u32, encode_varint_u32};

pub const VERSION_NIBBLE_V0: u8 = 0;
pub const HDR_KEY_PHASE: u8 = 0x02;
pub const FRAME_CRITICAL: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    StreamOpen = 0x01,
    StreamData = 0x02,
    StreamReset = 0x03,
    StreamWindow = 0x04,
    Datagram = 0x10,
    DatagramClose = 0x11,
    Control = 0x20,
    Ping = 0x2F,
    Pong = 0x30,
    PaddingOnly = 0x7F,
}

impl FrameType {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0x01 => Self::StreamOpen,
            0x02 => Self::StreamData,
            0x03 => Self::StreamReset,
            0x04 => Self::StreamWindow,
            0x10 => Self::Datagram,
            0x11 => Self::DatagramClose,
            0x20 => Self::Control,
            0x2F => Self::Ping,
            0x30 => Self::Pong,
            0x7F => Self::PaddingOnly,
            x => return Err(Error::UnknownFrameType(x)),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CtrlType {
    Caps = 1,
    MaskOffer = 2,
    MaskAck = 3,
    Health = 4,
    Backoff = 5,
    Rekey = 6,
    Close = 7,
    Ticket = 8,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HdrFlags(pub u8);

impl HdrFlags {
    pub fn new(version_nibble: u8, flags: u8) -> Self {
        Self(((version_nibble & 0x0f) << 4) | (flags & 0x0f))
    }

    pub fn version_nibble(self) -> u8 {
        self.0 >> 4
    }

    pub fn key_phase(self) -> bool {
        self.0 & HDR_KEY_PHASE != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHdr {
    pub flags: HdrFlags,
}

impl RecordHdr {
    pub fn v0() -> Self {
        Self {
            flags: HdrFlags::new(VERSION_NIBBLE_V0, 0),
        }
    }

    pub fn encode(self) -> u8 {
        self.flags.0
    }

    pub fn decode(b: u8) -> Self {
        Self {
            flags: HdrFlags(b),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameFlags(pub u8);

impl FrameFlags {
    pub fn critical(self) -> bool {
        self.0 & FRAME_CRITICAL != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub ty: FrameType,
    pub flags: FrameFlags,
    pub body: Bytes,
}

impl Frame {
    pub fn new(ty: FrameType, body: impl Into<Bytes>) -> Self {
        Self {
            ty,
            flags: FrameFlags(0),
            body: body.into(),
        }
    }

    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u8(self.ty as u8);
        out.put_u8(self.flags.0);
        let mut tmp = Vec::new();
        encode_varint_u32(self.body.len() as u32, &mut tmp);
        out.extend_from_slice(&tmp);
        out.extend_from_slice(&self.body);
    }

    pub fn encode_vec(&self) -> Vec<u8> {
        let mut bm = BytesMut::new();
        self.encode(&mut bm);
        bm.to_vec()
    }

    /// Decode one frame; returns (frame, bytes_consumed). Remaining may be padding.
    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < 2 {
            return Err(Error::BufferTooShort);
        }
        let ty = FrameType::from_u8(input[0])?;
        let flags = FrameFlags(input[1]);
        let (blen, vn) = decode_varint_u32(&input[2..])?;
        let start = 2 + vn;
        let end = start
            .checked_add(blen as usize)
            .ok_or(Error::InvalidLength)?;
        if end > input.len() {
            return Err(Error::BufferTooShort);
        }
        let body = Bytes::copy_from_slice(&input[start..end]);
        Ok((
            Self {
                ty,
                flags,
                body,
            },
            end,
        ))
    }

    /// Parse first frame; leftover treated as pad (not an error).
    pub fn decode_with_pad(input: &[u8]) -> Result<(Self, usize)> {
        Self::decode(input)
    }
}

/// Helper bodies for common frames.
pub mod bodies {
    use bytes::{BufMut, Bytes, BytesMut};

    use super::Frame;
    use crate::frame::FrameType;
    use crate::varint::encode_varint_u32;

    pub fn stream_data(stream_id: u32, data: &[u8]) -> Frame {
        let mut b = BytesMut::with_capacity(4 + data.len());
        b.put_u32(stream_id);
        b.extend_from_slice(data);
        Frame::new(FrameType::StreamData, b.freeze())
    }

    pub fn parse_stream_data(body: &[u8]) -> Option<(u32, &[u8])> {
        if body.len() < 4 {
            return None;
        }
        let id = u32::from_be_bytes(body[0..4].try_into().ok()?);
        Some((id, &body[4..]))
    }

    pub fn ping(opaque: &[u8]) -> Frame {
        Frame::new(FrameType::Ping, Bytes::copy_from_slice(opaque))
    }

    pub fn control(ctrl: u16, payload: &[u8]) -> Frame {
        let mut b = BytesMut::with_capacity(2 + payload.len());
        b.put_u16(ctrl);
        b.extend_from_slice(payload);
        Frame::new(FrameType::Control, b.freeze())
    }

    pub fn stream_open(stream_id: u32, initial_window: u32, meta: &[u8]) -> Frame {
        let mut b = BytesMut::new();
        b.put_u32(stream_id);
        b.put_u32(initial_window);
        let mut tmp = Vec::new();
        encode_varint_u32(meta.len() as u32, &mut tmp);
        b.extend_from_slice(&tmp);
        b.extend_from_slice(meta);
        Frame::new(FrameType::StreamOpen, b.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::bodies;

    #[test]
    fn stream_data_roundtrip() {
        let f = bodies::stream_data(300, b"A");
        let enc = f.encode_vec();
        // type=02 flags=00 body_len=5 → stream_id(4)+A
        assert_eq!(enc[0], 0x02);
        assert_eq!(enc[1], 0x00);
        let (dec, n) = Frame::decode(&enc).unwrap();
        assert_eq!(n, enc.len());
        assert_eq!(dec.ty, FrameType::StreamData);
        let (id, data) = bodies::parse_stream_data(&dec.body).unwrap();
        assert_eq!(id, 300);
        assert_eq!(data, b"A");
    }

    #[test]
    fn pad_after_frame() {
        let f = bodies::ping(b"");
        let mut buf = f.encode_vec();
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let (dec, n) = Frame::decode_with_pad(&buf).unwrap();
        assert_eq!(dec.ty, FrameType::Ping);
        assert_eq!(&buf[n..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn record_hdr_v0() {
        let h = RecordHdr::v0();
        assert_eq!(h.encode(), 0x00);
        assert_eq!(RecordHdr::decode(0x00).flags.version_nibble(), 0);
    }
}
