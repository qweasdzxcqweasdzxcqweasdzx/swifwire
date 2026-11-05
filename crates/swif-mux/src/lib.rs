//! Stream mux + datagram associations.

use rand::Rng;
use std::collections::HashMap;
use swif_wire::bodies;
use swif_wire::{Frame, FrameType};

pub const DEFAULT_WINDOW: u32 = 256 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unknown stream {0}")]
    UnknownStream(u32),
    #[error("window exceeded")]
    Window,
    #[error("bad frame")]
    BadFrame,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct StreamState {
    pub id: u32,
    pub send_credit: u32,
    pub recv_credit: u32,
    pub meta: Vec<u8>,
}

#[derive(Default)]
pub struct Mux {
    streams: HashMap<u32, StreamState>,
    is_client: bool,
}

impl Mux {
    pub fn new_client() -> Self {
        Self {
            streams: HashMap::new(),
            is_client: true,
        }
    }

    pub fn new_server() -> Self {
        Self {
            streams: HashMap::new(),
            is_client: false,
        }
    }

    /// Client opens stream with random odd id.
    pub fn open_stream(&mut self, meta: Vec<u8>) -> (u32, Frame) {
        let mut rng = rand::thread_rng();
        let mut id;
        loop {
            let raw: u32 = rng.gen();
            id = if self.is_client {
                (raw & !1) | 1 // odd
            } else {
                raw & !1 // even
            };
            if id != 0 && !self.streams.contains_key(&id) {
                break;
            }
        }
        self.streams.insert(
            id,
            StreamState {
                id,
                send_credit: DEFAULT_WINDOW,
                recv_credit: DEFAULT_WINDOW,
                meta: meta.clone(),
            },
        );
        (id, bodies::stream_open(id, DEFAULT_WINDOW, &meta))
    }

    pub fn accept_open(&mut self, frame: &Frame) -> Result<u32> {
        if frame.ty != FrameType::StreamOpen || frame.body.len() < 8 {
            return Err(Error::BadFrame);
        }
        let id = u32::from_be_bytes(frame.body[0..4].try_into().unwrap());
        let window = u32::from_be_bytes(frame.body[4..8].try_into().unwrap());
        self.streams.insert(
            id,
            StreamState {
                id,
                send_credit: window,
                recv_credit: DEFAULT_WINDOW,
                meta: frame.body[8..].to_vec(),
            },
        );
        Ok(id)
    }

    pub fn data_frame(&mut self, stream_id: u32, data: &[u8]) -> Result<Frame> {
        let st = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Error::UnknownStream(stream_id))?;
        if data.len() as u32 > st.send_credit {
            return Err(Error::Window);
        }
        st.send_credit -= data.len() as u32;
        Ok(bodies::stream_data(stream_id, data))
    }

    pub fn on_data(&mut self, frame: &Frame) -> Result<(u32, Vec<u8>)> {
        let (id, data) = bodies::parse_stream_data(&frame.body).ok_or(Error::BadFrame)?;
        let st = self
            .streams
            .get_mut(&id)
            .ok_or(Error::UnknownStream(id))?;
        if data.len() as u32 > st.recv_credit {
            return Err(Error::Window);
        }
        st.recv_credit -= data.len() as u32;
        Ok((id, data.to_vec()))
    }

    /// UDP associate / datagram: body = assoc_id(u32) || payload.
    pub fn datagram_frame(assoc_id: u32, payload: &[u8]) -> Frame {
        let mut b = Vec::with_capacity(4 + payload.len());
        b.extend_from_slice(&assoc_id.to_be_bytes());
        b.extend_from_slice(payload);
        Frame::new(FrameType::Datagram, b)
    }

    pub fn parse_datagram(frame: &Frame) -> Result<(u32, Vec<u8>)> {
        if frame.ty != FrameType::Datagram || frame.body.len() < 4 {
            return Err(Error::BadFrame);
        }
        let id = u32::from_be_bytes(frame.body[0..4].try_into().unwrap());
        Ok((id, frame.body[4..].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_data() {
        let mut c = Mux::new_client();
        let mut s = Mux::new_server();
        let (id, open) = c.open_stream(b"meta".to_vec());
        assert!(id % 2 == 1);
        s.accept_open(&open).unwrap();
        let f = c.data_frame(id, b"hi").unwrap();
        let (rid, data) = s.on_data(&f).unwrap();
        assert_eq!(rid, id);
        assert_eq!(data, b"hi");
    }

    #[test]
    fn datagram_roundtrip() {
        let f = Mux::datagram_frame(7, b"udp-payload");
        let (id, data) = Mux::parse_datagram(&f).unwrap();
        assert_eq!(id, 7);
        assert_eq!(data, b"udp-payload");
    }
}
