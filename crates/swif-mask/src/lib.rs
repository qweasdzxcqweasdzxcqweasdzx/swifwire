//! Mask drivers: `null_tcp`, `tls13_stable`, `quic_fast` + signed packs + cover.

mod cover;
mod io;
mod pack;
mod probe;
mod quic_fast;
mod quic_stable;
mod tls13;
mod tls_profile;
mod tls_provider;

pub use cover::{
    mirror_to_upstream, run_lab_cover, serve_builtin_http, serve_cover, CoverMode, COVER_HTML,
};
pub use probe::cover_looks_like_http_origin;
pub use io::{plausible_hello_len, read_pref, read_pref_timeout, write_pref};
pub use pack::{
    sign_pack_value, verify_and_load, MaskPack, MaskProfile, PackError, PackSignature,
};
pub use quic_fast::{
    decode_pref_datagram, encode_pref_datagram, encode_pref_datagram_slice, random_dcid,
    random_dcid_var, unwrap_payload, wrap_payload, QuicFastClient, COVER_VERSION, DCID_LEN,
};
pub use quic_stable::{is_runtime_ready as quic_stable_ready, status_message as quic_stable_status, QuicStableHints, PROFILE_ID as QUIC_STABLE};
pub use tls_profile::{ClientHelloProfile, TlsPackHints};
pub use tls_provider::{provider_for_profile, suite_order_ids};
pub use tls13::{
    accept_tls, dial_tls, dial_tls_verify, parse_tls_verify, write_pem, LabTlsMaterial,
    TlsVerifyMode,
};

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
        // Thin UDP cover — lab alias; prod DialPolicy must not prefer this (WP3 → quic_stable).
        "quic_fast" | "quic_lab" => Some("quic_fast"),
        "quic_stable" => Some("quic_stable"),
        _ => None,
    }
}
