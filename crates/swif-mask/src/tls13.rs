//! `tls13_stable` — TLS 1.3 underlay (lab pin / webpki / PEM material).

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTls;
use tokio_rustls::server::TlsStream as ServerTls;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// How the client verifies the cover TLS certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TlsVerifyMode {
    /// Lab: exact DER pin to `LabTlsMaterial.cert_der`.
    #[default]
    Pin,
    /// Prod: webpki Mozilla roots (+ optional future SPKI pin).
    Webpki,
}

#[derive(Clone)]
pub struct LabTlsMaterial {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub server_name: String,
}

impl LabTlsMaterial {
    /// Generate self-signed cert for lab SNI (default `cover.local`).
    pub fn generate(server_name: &str) -> std::io::Result<Self> {
        let mut params = rcgen::CertificateParams::new(vec![server_name.to_string()])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, server_name);
        let key = rcgen::KeyPair::generate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(Self {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
            server_name: server_name.to_string(),
        })
    }

    pub fn acceptor(&self) -> std::io::Result<TlsAcceptor> {
        let cert = CertificateDer::from(self.cert_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(TlsAcceptor::from(Arc::new(cfg)))
    }

    pub fn connector_pin(&self) -> std::io::Result<TlsConnector> {
        let verifier = Arc::new(PinCertVerifier {
            expect: self.cert_der.clone(),
        });
        let cfg = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(cfg)))
    }

    pub fn connector_webpki(&self) -> std::io::Result<TlsConnector> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(cfg)))
    }

    pub fn connector(&self, mode: TlsVerifyMode) -> std::io::Result<TlsConnector> {
        match mode {
            TlsVerifyMode::Pin => self.connector_pin(),
            TlsVerifyMode::Webpki => self.connector_webpki(),
        }
    }

    /// Load leaf cert + PKCS8 key from PEM files (prod cover material).
    pub fn from_pem_files(
        cert_path: &Path,
        key_path: &Path,
        server_name: &str,
    ) -> std::io::Result<Self> {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        Self::from_pem_bytes(&cert_pem, &key_pem, server_name)
    }

    pub fn from_pem_bytes(
        cert_pem: &[u8],
        key_pem: &[u8],
        server_name: &str,
    ) -> std::io::Result<Self> {
        let certs = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if certs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no CERTIFICATE in PEM",
            ));
        }
        let key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no PRIVATE KEY in PEM")
            })?;
        Ok(Self {
            cert_der: certs[0].as_ref().to_vec(),
            key_der: key.secret_der().to_vec(),
            server_name: server_name.to_string(),
        })
    }

    /// Acceptor with full chain (leaf first) when PEM had intermediates.
    pub fn acceptor_with_chain(&self, chain_ders: Vec<Vec<u8>>) -> std::io::Result<TlsAcceptor> {
        let mut certs: Vec<CertificateDer<'static>> = chain_ders
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        if certs.is_empty() {
            certs.push(CertificateDer::from(self.cert_der.clone()));
        }
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        Ok(TlsAcceptor::from(Arc::new(cfg)))
    }
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
            Err(TlsError::General("cert pin mismatch".into()))
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

pub async fn dial_tls(
    addr: std::net::SocketAddr,
    material: &LabTlsMaterial,
) -> std::io::Result<ClientTls<TcpStream>> {
    dial_tls_verify(addr, material, TlsVerifyMode::Pin).await
}

pub async fn dial_tls_verify(
    addr: std::net::SocketAddr,
    material: &LabTlsMaterial,
    verify: TlsVerifyMode,
) -> std::io::Result<ClientTls<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let connector = material.connector(verify)?;
    let name = ServerName::try_from(material.server_name.clone())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    connector.connect(name, tcp).await
}

pub fn parse_tls_verify(s: &str) -> Option<TlsVerifyMode> {
    match s {
        "pin" | "lab" => Some(TlsVerifyMode::Pin),
        "webpki" | "system" | "prod" => Some(TlsVerifyMode::Webpki),
        _ => None,
    }
}

pub async fn accept_tls(
    tcp: TcpStream,
    acceptor: &TlsAcceptor,
) -> std::io::Result<ServerTls<TcpStream>> {
    acceptor.accept(tcp).await
}

pub fn write_pem(
    material: &LabTlsMaterial,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> std::io::Result<()> {
    let cert_pem = pem_block("CERTIFICATE", &material.cert_der);
    let key_pem = pem_block("PRIVATE KEY", &material.key_der);
    std::fs::write(cert_path, cert_pem)?;
    std::fs::write(key_path, key_pem)?;
    Ok(())
}

fn pem_block(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut body = String::new();
    for chunk in b64.as_bytes().chunks(64) {
        body.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        body.push('\n');
    }
    format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
}
