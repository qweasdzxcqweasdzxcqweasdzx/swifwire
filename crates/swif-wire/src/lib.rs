//! SwifWire v0 — framing & varints (normative companion to docs/WIRE.md).

mod control;
mod error;
mod frame;
mod varint;

pub use control::{
    backoff, early_ctrl, health, mask_ack, mask_offer, parse_backoff, parse_ctrl, parse_early_ctrl,
    parse_health, parse_mask_ack, parse_mask_offer, parse_rekey, rekey,
};
pub use error::{Error, Result};
pub use frame::bodies;
pub use frame::{
    CtrlType, Frame, FrameFlags, FrameType, HdrFlags, RecordHdr, FRAME_CRITICAL, HDR_KEY_PHASE,
    VERSION_NIBBLE_V0,
};
pub use varint::{decode_varint_u32, decode_varint_u64, encode_varint_u32, encode_varint_u64};

/// Inner handshake magic "SWI1" — only inside mask payload, never bare on TCP.
pub const MAGIC_INNER: [u8; 4] = *b"SWI1";
pub const PROTOCOL_VERSION: u16 = 0;
