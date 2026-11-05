//! Session record layer: handshake helpers, seal/open with counters + shaper.

mod error;
mod handshake;
mod reconnect;
mod transport;

pub use error::{Error, Result};
pub use handshake::{
    client_finish_keys, client_finish_keys_ex, client_finish_resume, client_hello_inner,
    client_resume_hello, resume_psk_from_shared, server_hello_ticket, server_respond_keys,
    server_respond_keys_ex, ClientHelloInner, HandshakeRole, ServerHelloInner,
};
pub use transport::{Direction, SessionTransport};
