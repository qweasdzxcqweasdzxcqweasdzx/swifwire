//! `quic_stable` — pack-driven QUIC underlay (WP3).
//!
//! ## Framing
//! Bidirectional QUIC stream 0 carries length-prefixed SwifHS + AEAD records
//! (same pref framing as TCP masks — [`PrefStreamBuf`] / `read_pref`/`write_pref`).
//!
//! ## Status
//! Quinn dial/accept is wired for lab (`SWIF_ALLOW_QUIC_STABLE=1`). Pack Initial
//! template mimicry is still open; ALPN/SNI come from [`QuicStableHints`].

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, ServerConfig as RustlsServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::pack::MaskProfile;
use crate::tls13::{LabTlsMaterial, TlsVerifyMode};
use crate::tls_provider::provider_for_profile;

pub const PROFILE_ID: &str = "quic_stable";

/// Max single pref record on a QUIC stream (matches TCP `read_pref`).
pub const MAX_PREF_RECORD: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct QuicStableHints {
    pub alpn: Vec<String>,
    pub sni_pool_ref: Option<String>,
    pub has_initial_template: bool,
}

impl Default for QuicStableHints {
    fn default() -> Self {
        Self {
            alpn: vec!["h3".into()],
            sni_pool_ref: None,
            has_initial_template: false,
        }
    }
}

impl QuicStableHints {
    pub fn from_mask_profile(p: &MaskProfile) -> Self {
        let mut h = Self::default();
        if let Some(b64) = p
            .templates
            .get("quic_initial_b64")
            .and_then(|v| v.as_str())
        {
            h.has_initial_template = !b64.is_empty();
        }
        if let Some(cover) = &p.cover {
            if let Some(arr) = cover.get("alpn").and_then(|v| v.as_array()) {
                let list: Vec<String> = arr
                    .iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect();
                if !list.is_empty() {
                    h.alpn = list;
                }
            }
            h.sni_pool_ref = cover
                .get("sni_pool_ref")
                .and_then(|v| v.as_str())
                .map(str::to_string);
        }
        h
    }

    pub fn alpn_wire(&self) -> Vec<Vec<u8>> {
        self.alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
    }
}

/// Encode one length-prefixed record for a reliable QUIC stream (stream 0).
pub fn encode_pref_record(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + msg.len());
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefStreamError {
    TooLarge,
}

impl std::fmt::Display for PrefStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "pref record too large"),
        }
    }
}

impl std::error::Error for PrefStreamError {}

/// Incremental decoder for length-prefixed records on an ordered byte stream.
#[derive(Debug, Default)]
pub struct PrefStreamBuf {
    buf: Vec<u8>,
}

impl PrefStreamBuf {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    pub fn pop_record(&mut self) -> Result<Option<Vec<u8>>, PrefStreamError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let n = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if n > MAX_PREF_RECORD {
            return Err(PrefStreamError::TooLarge);
        }
        if self.buf.len() < 4 + n {
            return Ok(None);
        }
        let msg = self.buf[4..4 + n].to_vec();
        self.buf.drain(..4 + n);
        Ok(Some(msg))
    }

    pub fn pop_all(&mut self) -> Result<Vec<Vec<u8>>, PrefStreamError> {
        let mut out = Vec::new();
        while let Some(r) = self.pop_record()? {
            out.push(r);
        }
        Ok(out)
    }
}

/// Quinn bidirectional stream used as SwifWire underlay (AsyncRead + AsyncWrite).
pub struct QuicStableStream {
    send: SendStream,
    recv: RecvStream,
}

impl QuicStableStream {
    pub fn from_bi(send: SendStream, recv: RecvStream) -> Self {
        Self { send, recv }
    }
}

/// Client session: owns the local [`Endpoint`] so the connection stays alive.
pub struct QuicStableClient {
    /// Must outlive `conn` / `stream`.
    pub endpoint: Endpoint,
    pub conn: Connection,
    pub stream: QuicStableStream,
}

/// Server accept result (caller keeps the listening [`Endpoint`]).
pub struct QuicStableAccepted {
    pub conn: Connection,
    pub stream: QuicStableStream,
}

impl AsyncRead for QuicStableStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStableStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// True when quinn dial/accept path is compiled in.
pub fn is_runtime_ready() -> bool {
    true
}

pub fn status_message() -> &'static str {
    "quic_stable: quinn dial/accept + PrefStreamBuf on bi-stream; set SWIF_ALLOW_QUIC_STABLE=1 (lab)"
}

pub fn lab_allowed() -> bool {
    std::env::var("SWIF_ALLOW_QUIC_STABLE").ok().as_deref() == Some("1")
        || std::env::var("SWIF_LAB").ok().as_deref() == Some("1")
}

fn io_other(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e.to_string())
}

fn quic_alpn(material: &LabTlsMaterial, hints: &QuicStableHints) -> Vec<Vec<u8>> {
    let wire = hints.alpn_wire();
    if !wire.is_empty() {
        return wire;
    }
    // Fall back to TLS pack ALPN if quic hints empty.
    material.hints.alpn_wire()
}

fn build_server_config(
    material: &LabTlsMaterial,
    hints: &QuicStableHints,
) -> io::Result<ServerConfig> {
    let cert = CertificateDer::from(material.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.key_der.clone()));
    let provider = provider_for_profile(material.hints.profile);
    let mut crypto = RustlsServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io_other)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(io_other)?;
    crypto.alpn_protocols = quic_alpn(material, hints);
    crypto.max_early_data_size = u32::MAX;
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(crypto).map_err(io_other)?;
    Ok(ServerConfig::with_crypto(Arc::new(quic)))
}

fn build_client_config(
    material: &LabTlsMaterial,
    hints: &QuicStableHints,
    verify: TlsVerifyMode,
) -> io::Result<ClientConfig> {
    let provider = provider_for_profile(material.hints.profile);
    let builder = RustlsClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(io_other)?;
    let mut crypto = match verify {
        TlsVerifyMode::Pin => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinCertVerifier {
                expect: material.cert_der.clone(),
            }))
            .with_no_client_auth(),
        TlsVerifyMode::Webpki => {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            builder
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
    };
    crypto.alpn_protocols = quic_alpn(material, hints);
    crypto.enable_early_data = true;
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(io_other)?;
    Ok(ClientConfig::new(Arc::new(quic)))
}

#[derive(Debug)]
struct PinCertVerifier {
    expect: Vec<u8>,
}

impl ServerCertVerifier for PinCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.expect.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::General("quic pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// Bind a quinn server endpoint for `quic_stable`.
pub fn bind_server(
    listen: SocketAddr,
    material: &LabTlsMaterial,
    hints: &QuicStableHints,
) -> io::Result<Endpoint> {
    let cfg = build_server_config(material, hints)?;
    Endpoint::server(cfg, listen).map_err(io_other)
}

/// Accept one connection and its first bidirectional stream (SwifWire pipe).
pub async fn accept_bi(endpoint: &Endpoint) -> io::Result<QuicStableAccepted> {
    let incoming = endpoint
        .accept()
        .await
        .ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "endpoint closed"))?;
    let conn = incoming.await.map_err(io_other)?;
    let (send, recv) = conn.accept_bi().await.map_err(io_other)?;
    Ok(QuicStableAccepted {
        conn,
        stream: QuicStableStream::from_bi(send, recv),
    })
}

/// Dial peer and open bidirectional stream 0.
pub async fn dial(
    peer: SocketAddr,
    material: &LabTlsMaterial,
    hints: &QuicStableHints,
    verify: TlsVerifyMode,
) -> io::Result<QuicStableClient> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).map_err(io_other)?;
    endpoint.set_default_client_config(build_client_config(material, hints, verify)?);
    let sni = material.server_name.clone();
    let conn = endpoint
        .connect(peer, &sni)
        .map_err(io_other)?
        .await
        .map_err(io_other)?;
    let (send, recv) = conn.open_bi().await.map_err(io_other)?;
    Ok(QuicStableClient {
        endpoint,
        conn,
        stream: QuicStableStream::from_bi(send, recv),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{read_pref, write_pref};
    use serde_json::json;

    #[test]
    fn runtime_ready() {
        assert!(is_runtime_ready());
        assert!(!status_message().is_empty());
    }

    #[test]
    fn parses_hints() {
        let p = MaskProfile {
            id: PROFILE_ID.into(),
            underlay: "udp".into(),
            default_port: Some(443),
            shaper: json!({}),
            templates: json!({"quic_initial_b64": "AAAA"}),
            cover: Some(json!({"alpn": ["h3"], "sni_pool_ref": "q.v1"})),
        };
        let h = QuicStableHints::from_mask_profile(&p);
        assert!(h.has_initial_template);
        assert_eq!(h.alpn, vec!["h3"]);
    }

    #[test]
    fn pref_stream_chunked_roundtrip() {
        let a = encode_pref_record(b"hello");
        let b = encode_pref_record(b"world-swif");
        let mut wire = Vec::new();
        wire.extend_from_slice(&a);
        wire.extend_from_slice(&b);

        let mut dec = PrefStreamBuf::new();
        for chunk in wire.chunks(3) {
            dec.push(chunk);
        }
        let msgs = dec.pop_all().unwrap();
        assert_eq!(msgs, vec![b"hello".to_vec(), b"world-swif".to_vec()]);
        assert_eq!(dec.pending(), 0);
    }

    #[test]
    fn pref_stream_rejects_huge() {
        let mut dec = PrefStreamBuf::new();
        let n = (MAX_PREF_RECORD as u32).saturating_add(1).to_be_bytes();
        dec.push(&n);
        assert_eq!(dec.pop_record(), Err(PrefStreamError::TooLarge));
    }

    #[tokio::test]
    async fn quinn_pref_roundtrip() {
        let material = LabTlsMaterial::generate("cover.local").unwrap();
        let hints = QuicStableHints::default();
        let endpoint = bind_server("127.0.0.1:0".parse().unwrap(), &material, &hints).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (hold_tx, hold_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let mut accepted = accept_bi(&endpoint).await.unwrap();
            let msg = read_pref(&mut accepted.stream).await.unwrap();
            write_pref(&mut accepted.stream, &msg).await.unwrap();
            // Keep QUIC connection alive until the client finishes reading.
            let _ = hold_rx.await;
            msg
        });

        let mut client = dial(addr, &material, &hints, TlsVerifyMode::Pin)
            .await
            .unwrap();
        write_pref(&mut client.stream, b"quic-stable-ping")
            .await
            .unwrap();
        let echo = read_pref(&mut client.stream).await.unwrap();
        assert_eq!(echo, b"quic-stable-ping");
        let _ = hold_tx.send(());
        assert_eq!(server.await.unwrap(), b"quic-stable-ping");
        drop(client);
    }
}
