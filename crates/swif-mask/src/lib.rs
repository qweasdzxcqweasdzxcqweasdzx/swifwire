//! Mask drivers: `null_tcp`, `tls13_stable`, `quic_fast` + signed packs + cover.

mod cover;
mod io;
mod pack;
mod probe;
mod quic_fast;
mod tls13;

pub use cover::{mirror_to_upstream, run_lab_cover, serve_builtin_http, COVER_HTML};
pub use probe::cover_looks_like_http_origin;
pub use io::{plausible_hello_len, read_pref, write_pref};
pub use pack::{
    sign_pack_value, verify_and_load, MaskPack, MaskProfile, PackError, PackSignature,
};
pub use quic_fast::{
    decode_pref_datagram, encode_pref_datagram, random_dcid, unwrap_payload, wrap_payload,
    QuicFastClient, COVER_VERSION, DCID_LEN,
};
pub use tls13::{accept_tls, dial_tls, write_pem, LabTlsMaterial};

use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[async_trait]
pub trait MaskDial: Send + Sync {
    async fn dial(&self, addr: SocketAddr) -> std::io::Result<TcpStream>;
}

pub struct NullTcp;

#[async_trait]
impl MaskDial for NullTcp {
    async fn dial(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

pub fn parse_profile(id: &str) -> Option<&'static str> {
    match id {
        "null_tcp" => Some("null_tcp"),
        "tls13_stable" => Some("tls13_stable"),
        "quic_fast" => Some("quic_fast"),
        _ => None,
    }
}
