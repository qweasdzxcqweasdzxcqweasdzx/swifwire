//! KDF, AEAD records, X25519 helpers for SwifWire v0.

mod aead;
mod ed25519;
mod error;
mod kdf;
mod replay;
mod ticket;
mod x25519;

pub use aead::{open_record, seal_record, AeadKey, NonceSalt, TAG_LEN};
pub use ed25519::{PackSigningKey, PackVerifyingKey};
pub use error::{Error, Result};
pub use kdf::{
    derive_rekey_keys, derive_session_keys, SessionKeys, LABEL_C2S, LABEL_NONCE, LABEL_REKEY,
    LABEL_S2C, LABEL_TICKET,
};
pub use replay::TicketReplayWindow;
pub use ticket::{open_ticket, seal_ticket, ticket_expired};
pub use x25519::{public_from_bytes, EphemeralKeypair, SharedSecret, StaticKeypair};
