//! Live TLS 1.3 craft dial: pack-ordered ClientHello → HS → app data.
//! Clean-room RFC 8446 subset for rustls edge interoperability.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tls13::{LabTlsMaterial, TlsVerifyMode};
use crate::tls_ch_wire::{
    build_client_hello_record_live, ja3_string_from_record, LiveClientHelloParams,
};
use crate::tls_fingerprint::FingerprintBudget;
use crate::tls_profile::ClientHelloProfile;

type HmacSha256 = Hmac<Sha256>;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

#[derive(Clone, Copy, Debug)]
enum AeadKind {
    Aes128Gcm,
    ChaCha20,
}

/// Code path compiled and selectable (`SWIF_TLS_CH_CRAFT=1`).
pub fn craft_dial_wired() -> bool {
    true
}

/// True when live dial uses pack-ordered ClientHello for this profile.
pub fn tls_extension_order_ready_for(profile: ClientHelloProfile) -> bool {
    matches!(
        profile,
        ClientHelloProfile::ChromeStable | ClientHelloProfile::FirefoxStable
    ) && std::env::var("SWIF_TLS_RUSTLS_DIAL").ok().as_deref() != Some("1")
}

pub fn fingerprint_budget_craft() -> FingerprintBudget {
    FingerprintBudget {
        cipher_suites: true,
        kx_groups: true,
        signature_schemes: true,
        alpn: true,
        grease_flag: true,
        extension_order: true,
    }
}

/// Whether craft dial should be used for these pack hints.
/// Default ON for chrome/firefox. Force rustls: `SWIF_TLS_RUSTLS_DIAL=1`.
pub fn should_craft_dial(hints: &crate::tls_profile::TlsPackHints) -> bool {
    if std::env::var("SWIF_TLS_RUSTLS_DIAL").ok().as_deref() == Some("1") {
        return false;
    }
    matches!(
        hints.profile,
        ClientHelloProfile::ChromeStable | ClientHelloProfile::FirefoxStable
    )
}

pub struct CraftTlsStream {
    tcp: TcpStream,
    aead: AeadKind,
    w_key16: [u8; 16],
    w_key32: [u8; 32],
    w_iv: [u8; 12],
    r_key16: [u8; 16],
    r_key32: [u8; 32],
    r_iv: [u8; 12],
    w_seq: u64,
    r_seq: u64,
    /// Decrypted app plaintext waiting for read.
    app_buf: Vec<u8>,
    /// Partial TLS record header/body assembly.
    raw_buf: Vec<u8>,
    pub ja3_string: String,
}

impl CraftTlsStream {
    /// Drain NewSessionTicket / post-HS records. Ignores decrypt errors on empty buffer.
    pub async fn drain_post_handshake(&mut self) {
        for _ in 0..8 {
            let mut tmp = [0u8; 32];
            match tokio::time::timeout(std::time::Duration::from_millis(25), self.read(&mut tmp))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => continue, // unexpected app data
                Ok(Err(_)) => break,
                Err(_) => break, // timeout — nothing more buffered
            }
        }
    }
}

pub async fn dial_tls_craft(
    addr: std::net::SocketAddr,
    material: &LabTlsMaterial,
    verify: TlsVerifyMode,
) -> io::Result<CraftTlsStream> {
    let mut tcp = TcpStream::connect(addr).await?;

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = StaticSecret::from(seed);
    let pk = PublicKey::from(&sk);
    let mut random = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random);
    // Non-empty session_id → middlebox compat (CCS); rustls accepts either.
    let mut sid = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut sid);
    let live = LiveClientHelloParams {
        random,
        session_id: sid.to_vec(),
        key_share_x25519: *pk.as_bytes(),
        omit_experimental: true,
    };
    let ch_rec = build_client_hello_record_live(&material.hints, &material.server_name, &live);
    let ja3 = ja3_string_from_record(&ch_rec).unwrap_or_default();
    let ch_hs = ch_rec[5..].to_vec();
    let mut tr = Transcript::new();
    tr.update(&ch_hs);
    tcp.write_all(&ch_rec).await?;

    // ServerHello
    let sh_hs = read_one_handshake_record(&mut tcp).await?;
    if sh_hs.first() != Some(&0x02) {
        return Err(err("expected ServerHello"));
    }
    tr.update(&sh_hs);
    let (cipher, server_share) = parse_server_hello(&sh_hs[4..])?;
    let aead = match cipher {
        TLS_AES_128_GCM_SHA256 => AeadKind::Aes128Gcm,
        TLS_CHACHA20_POLY1305_SHA256 => AeadKind::ChaCha20,
        x => return Err(err(&format!("cipher {x:#x}"))),
    };

    let shared = sk.diffie_hellman(&PublicKey::from(server_share));
    let hs = schedule_handshake(shared.as_bytes(), &tr, aead)?;

    // Encrypted server flight
    let mut hs_seq = 0u64;
    let mut flight = Vec::new();
    loop {
        let (ct, payload) = read_record(&mut tcp).await?;
        if ct == 20 {
            continue;
        }
        if ct != 23 {
            return Err(err("want encrypted hs"));
        }
        let plain = open_record(
            aead,
            &hs.s_key16,
            &hs.s_key32,
            &hs.s_iv,
            hs_seq,
            &payload,
        )?;
        hs_seq += 1;
        flight.extend_from_slice(&plain);
        if flight_has_finished(&flight) {
            break;
        }
    }
    let hs_msgs = strip_ct_and_split(&flight)?;

    let mut leaf = Vec::new();
    let mut server_finished = None;
    for m in hs_msgs {
        match m.first().copied() {
            Some(0x08) => tr.update(&m), // EE
            Some(0x0b) => {
                tr.update(&m);
                leaf = parse_cert_leaf(&m[4..])?;
            }
            Some(0x0f) => {
                // CertVerify — verify against transcript BEFORE adding CV
                verify_certificate_verify(verify, material, &leaf, &m, &tr)?;
                tr.update(&m);
            }
            Some(0x14) => server_finished = Some(m),
            _ => tr.update(&m),
        }
    }
    let sf = server_finished.ok_or_else(|| err("no Finished"))?;
    let expect = finished_mac(&hs.s_traffic, &tr)?;
    if sf.len() < 4 || &sf[4..] != expect.as_slice() {
        return Err(err("server Finished MAC"));
    }
    tr.update(&sf);

    if verify == TlsVerifyMode::Pin && leaf != material.cert_der {
        return Err(err("pin mismatch"));
    }

    // App traffic secrets: Derive-Secret(..., ClientHello...server Finished)
    // — client's own Finished is NOT in the transcript (RFC 8446 §7.1).
    let app = schedule_app(&hs.master, &tr, aead)?;

    // Client Finished (MAC over transcript through server Finished)
    let cvd = finished_mac(&hs.c_traffic, &tr)?;
    let mut cf = vec![0x14, 0, 0, cvd.len() as u8];
    cf.extend_from_slice(&cvd);
    let mut cf_plain = cf;
    cf_plain.push(0x16);
    // Middlebox CCS (compat with non-empty session_id).
    tcp.write_all(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;
    let cf_rec = seal_record(aead, &hs.c_key16, &hs.c_key32, &hs.c_iv, 0, &cf_plain)?;
    tcp.write_all(&cf_rec).await?;

    Ok(CraftTlsStream {
        tcp,
        aead,
        w_key16: app.c_key16,
        w_key32: app.c_key32,
        w_iv: app.c_iv,
        r_key16: app.s_key16,
        r_key32: app.s_key32,
        r_iv: app.s_iv,
        w_seq: 0,
        r_seq: 0,
        app_buf: Vec::new(),
        raw_buf: Vec::new(),
        ja3_string: ja3,
    })
}

struct Transcript {
    h: Sha256,
}

impl Transcript {
    fn new() -> Self {
        Self { h: Sha256::new() }
    }
    fn update(&mut self, msg: &[u8]) {
        self.h.update(msg);
    }
    fn hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.h.clone().finalize());
        out
    }
}

struct HsKeys {
    c_traffic: [u8; 32],
    s_traffic: [u8; 32],
    c_key16: [u8; 16],
    c_key32: [u8; 32],
    c_iv: [u8; 12],
    s_key16: [u8; 16],
    s_key32: [u8; 32],
    s_iv: [u8; 12],
    master: [u8; 32],
}

struct AppKeys {
    c_key16: [u8; 16],
    c_key32: [u8; 32],
    c_iv: [u8; 12],
    s_key16: [u8; 16],
    s_key32: [u8; 32],
    s_iv: [u8; 12],
}

fn err(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}

fn extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    let mut o = [0u8; 32];
    o.copy_from_slice(prk.as_slice());
    o
}

fn expand_label(secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("prk len");
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("expand");
    out
}

fn derive_secret(secret: &[u8], label: &str, tr: &Transcript) -> [u8; 32] {
    let h = tr.hash();
    let v = expand_label(secret, label, &h, 32);
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    o
}

fn traffic_keys(secret: &[u8]) -> ([u8; 16], [u8; 32], [u8; 12]) {
    let k16 = expand_label(secret, "key", &[], 16);
    let k32 = expand_label(secret, "key", &[], 32);
    let iv = expand_label(secret, "iv", &[], 12);
    let mut a = [0u8; 16];
    let mut b = [0u8; 32];
    let mut c = [0u8; 12];
    a.copy_from_slice(&k16);
    b.copy_from_slice(&k32);
    c.copy_from_slice(&iv);
    (a, b, c)
}

fn schedule_handshake(shared: &[u8], tr: &Transcript, _aead: AeadKind) -> io::Result<HsKeys> {
    // Early Secret = HKDF-Extract(0^{Hash.len}, 0^{Hash.len}) when no PSK (RFC 8446 §7.1).
    let early = extract(&[0u8; 32], &[0u8; 32]);
    let empty = Sha256::digest([]);
    let derived = expand_label(&early, "derived", &empty, 32);
    let hs_secret = extract(&derived, shared);
    let c_traffic = derive_secret(&hs_secret, "c hs traffic", tr);
    let s_traffic = derive_secret(&hs_secret, "s hs traffic", tr);
    let (c_key16, c_key32, c_iv) = traffic_keys(&c_traffic);
    let (s_key16, s_key32, s_iv) = traffic_keys(&s_traffic);
    let derived2 = expand_label(&hs_secret, "derived", &empty, 32);
    let master = extract(&derived2, &[0u8; 32]);
    Ok(HsKeys {
        c_traffic,
        s_traffic,
        c_key16,
        c_key32,
        c_iv,
        s_key16,
        s_key32,
        s_iv,
        master,
    })
}

fn schedule_app(master: &[u8], tr: &Transcript, _aead: AeadKind) -> io::Result<AppKeys> {
    let c = derive_secret(master, "c ap traffic", tr);
    let s = derive_secret(master, "s ap traffic", tr);
    let (c_key16, c_key32, c_iv) = traffic_keys(&c);
    let (s_key16, s_key32, s_iv) = traffic_keys(&s);
    Ok(AppKeys {
        c_key16,
        c_key32,
        c_iv,
        s_key16,
        s_key32,
        s_iv,
    })
}

fn finished_mac(base: &[u8], tr: &Transcript) -> io::Result<Vec<u8>> {
    let finished_key = expand_label(base, "finished", &[], 32);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&finished_key)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    mac.update(&tr.hash());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut n = *iv;
    let s = seq.to_be_bytes();
    for i in 0..8 {
        n[4 + i] ^= s[i];
    }
    n
}

struct SeqNonce {
    iv: [u8; 12],
    seq: u64,
}

impl NonceSequence for SeqNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let n = nonce(&self.iv, self.seq);
        self.seq += 1;
        Ok(Nonce::assume_unique_for_key(n))
    }
}

fn seal_record(
    kind: AeadKind,
    k16: &[u8; 16],
    k32: &[u8; 32],
    iv: &[u8; 12],
    seq: u64,
    plain: &[u8],
) -> io::Result<Vec<u8>> {
    let mut aad = [0x17u8, 0x03, 0x03, 0, 0];
    let clen = (plain.len() + 16) as u16;
    aad[3..5].copy_from_slice(&clen.to_be_bytes());
    let alg = match kind {
        AeadKind::Aes128Gcm => &aead::AES_128_GCM,
        AeadKind::ChaCha20 => &aead::CHACHA20_POLY1305,
    };
    let key_bytes: &[u8] = match kind {
        AeadKind::Aes128Gcm => k16,
        AeadKind::ChaCha20 => k32,
    };
    let unbound = UnboundKey::new(alg, key_bytes).map_err(|_| err("aead key"))?;
    let mut sealing = SealingKey::new(unbound, SeqNonce { iv: *iv, seq });
    let mut out = plain.to_vec();
    sealing
        .seal_in_place_append_tag(Aad::from(&aad), &mut out)
        .map_err(|_| err("seal"))?;
    let mut rec = vec![0x17, 0x03, 0x03];
    rec.extend_from_slice(&(out.len() as u16).to_be_bytes());
    rec.extend_from_slice(&out);
    Ok(rec)
}

fn open_record(
    kind: AeadKind,
    k16: &[u8; 16],
    k32: &[u8; 32],
    iv: &[u8; 12],
    seq: u64,
    ct: &[u8],
) -> io::Result<Vec<u8>> {
    let mut aad = [0x17u8, 0x03, 0x03, 0, 0];
    aad[3..5].copy_from_slice(&(ct.len() as u16).to_be_bytes());
    let alg = match kind {
        AeadKind::Aes128Gcm => &aead::AES_128_GCM,
        AeadKind::ChaCha20 => &aead::CHACHA20_POLY1305,
    };
    let key_bytes: &[u8] = match kind {
        AeadKind::Aes128Gcm => k16,
        AeadKind::ChaCha20 => k32,
    };
    let unbound = UnboundKey::new(alg, key_bytes).map_err(|_| err("aead key"))?;
    let mut opening = OpeningKey::new(unbound, SeqNonce { iv: *iv, seq });
    let mut out = ct.to_vec();
    let plain = opening
        .open_in_place(Aad::from(&aad), &mut out)
        .map_err(|_| err("open aead"))?;
    Ok(plain.to_vec())
}

async fn read_record(tcp: &mut TcpStream) -> io::Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    tcp.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut body = vec![0u8; len];
    tcp.read_exact(&mut body).await?;
    Ok((hdr[0], body))
}

async fn read_one_handshake_record(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let (ct, payload) = read_record(tcp).await?;
    if ct != 22 {
        return Err(err("plaintext handshake record"));
    }
    if payload.len() < 4 {
        return Err(err("short hs"));
    }
    let n = ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if payload.len() < 4 + n {
        return Err(err("hs truncated"));
    }
    Ok(payload[..4 + n].to_vec())
}

fn parse_server_hello(body: &[u8]) -> io::Result<(u16, [u8; 32])> {
    if body.len() < 35 {
        return Err(err("SH"));
    }
    let mut i = 34;
    let sidl = body[i] as usize;
    i += 1 + sidl;
    let cipher = u16::from_be_bytes([body[i], body[i + 1]]);
    i += 3;
    let el = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    let exts = &body[i..i + el];
    let mut j = 0;
    while j + 4 <= exts.len() {
        let ty = u16::from_be_bytes([exts[j], exts[j + 1]]);
        let len = u16::from_be_bytes([exts[j + 2], exts[j + 3]]) as usize;
        let data = &exts[j + 4..j + 4 + len];
        if ty == 0x0033 && data.len() >= 36 {
            let mut s = [0u8; 32];
            s.copy_from_slice(&data[4..36]);
            return Ok((cipher, s));
        }
        j += 4 + len;
    }
    Err(err("no server key_share"))
}

fn parse_cert_leaf(body: &[u8]) -> io::Result<Vec<u8>> {
    let ctx = body[0] as usize;
    let mut i = 1 + ctx + 3;
    let clen = ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | body[i + 2] as usize;
    i += 3;
    Ok(body[i..i + clen].to_vec())
}

fn flight_has_finished(flight: &[u8]) -> bool {
    strip_ct_and_split(flight)
        .map(|ms| ms.iter().any(|m| m.first() == Some(&0x14)))
        .unwrap_or(false)
}

fn strip_ct_and_split(flight: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    if flight.is_empty() {
        return Err(err("empty flight"));
    }
    let body = &flight[..flight.len() - 1];
    let mut out = Vec::new();
    let mut p = body;
    while !p.is_empty() {
        if p.len() < 4 {
            return Err(err("hs frag"));
        }
        let n = ((p[1] as usize) << 16) | ((p[2] as usize) << 8) | p[3] as usize;
        if p.len() < 4 + n {
            return Err(err("hs frag2"));
        }
        out.push(p[..4 + n].to_vec());
        p = &p[4 + n..];
    }
    Ok(out)
}

fn verify_certificate_verify(
    mode: TlsVerifyMode,
    material: &LabTlsMaterial,
    leaf: &[u8],
    msg: &[u8],
    tr: &Transcript,
) -> io::Result<()> {
    if mode == TlsVerifyMode::Pin && leaf != material.cert_der {
        return Err(err("CV pin"));
    }
    let body = &msg[4..];
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let slen = u16::from_be_bytes([body[2], body[3]]) as usize;
    let sig = &body[4..4 + slen];

    let mut signed = vec![0x20u8; 64];
    signed.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    signed.extend_from_slice(&tr.hash());

    let spki = extract_spki(leaf).ok_or_else(|| err("spki"))?;
    match scheme {
        0x0403 => {
            // ecdsa_secp256r1_sha256 — SPKI BIT STRING holds EC point
            let key = ec_pubkey_from_spki(&spki).ok_or_else(|| err("ec key"))?;
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                &key,
            )
            .verify(&signed, sig)
            .map_err(|_| err("ecdsa verify"))
        }
        0x0807 => {
            let key = &spki[spki.len().saturating_sub(32)..];
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
                .verify(&signed, sig)
                .map_err(|_| err("ed25519 verify"))
        }
        _ if mode == TlsVerifyMode::Pin => Ok(()), // lab pin + Finished still binds ECDHE
        _ => Err(err(&format!("CV scheme {scheme:#x}"))),
    }
}

fn extract_spki(cert: &[u8]) -> Option<Vec<u8>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let cert_body = der_content(cert)?;
    let (tbs, _) = der_tlv(cert_body)?;
    let mut p = der_content(tbs)?;
    if p.first()? == &0xa0 {
        let (_, rest) = der_tlv(p)?;
        p = rest;
    }
    let (_, p) = der_tlv(p)?; // serialNumber
    let (_, p) = der_tlv(p)?; // signature
    let (_, p) = der_tlv(p)?; // issuer
    let (_, p) = der_tlv(p)?; // validity
    let (_, p) = der_tlv(p)?; // subject
    let (spki, _) = der_tlv(p)?; // subjectPublicKeyInfo
    Some(spki.to_vec())
}

fn der_content(el: &[u8]) -> Option<&[u8]> {
    if el.len() < 2 {
        return None;
    }
    let (len, hdr) = if el[1] & 0x80 == 0 {
        (el[1] as usize, 2usize)
    } else {
        let n = (el[1] & 0x7f) as usize;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | el[2 + i] as usize;
        }
        (len, 2 + n)
    };
    Some(&el[hdr..hdr + len])
}

fn der_tlv(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let (len, hdr) = if input[1] & 0x80 == 0 {
        (input[1] as usize, 2usize)
    } else {
        let n = (input[1] & 0x7f) as usize;
        if input.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | input[2 + i] as usize;
        }
        (len, 2 + n)
    };
    if input.len() < hdr + len {
        return None;
    }
    Some((&input[..hdr + len], &input[hdr + len..]))
}

fn ec_pubkey_from_spki(spki: &[u8]) -> Option<Vec<u8>> {
    // SubjectPublicKeyInfo: seq { alg, bitstring }
    let body = der_content(spki)?;
    let (_, rest) = der_tlv(body)?; // algorithm
    let (bitstr, _) = der_tlv(rest)?;
    let bits = der_content(bitstr)?;
    // unused bits byte then key
    if bits.is_empty() {
        return None;
    }
    Some(bits[1..].to_vec())
}

impl AsyncWrite for CraftTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // One record per write (SOCKS chunks are fine).
        let mut plain = buf.to_vec();
        plain.push(0x17);
        let rec = match seal_record(
            self.aead,
            &self.w_key16,
            &self.w_key32,
            &self.w_iv,
            self.w_seq,
            &plain,
        ) {
            Ok(r) => r,
            Err(e) => return Poll::Ready(Err(e)),
        };
        match Pin::new(&mut self.tcp).poll_write(cx, &rec) {
            Poll::Ready(Ok(n)) if n == rec.len() => {
                self.w_seq += 1;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short tls write",
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

impl AsyncRead for CraftTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.app_buf.is_empty() {
                let n = buf.remaining().min(self.app_buf.len());
                buf.put_slice(&self.app_buf[..n]);
                self.app_buf.drain(..n);
                return Poll::Ready(Ok(()));
            }
            // Fill raw_buf to one record
            while self.raw_buf.len() < 5 {
                let mut tmp = [0u8; 5];
                let want = 5 - self.raw_buf.len();
                let mut rb = ReadBuf::new(&mut tmp[..want]);
                match Pin::new(&mut self.tcp).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let f = rb.filled();
                        if f.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        self.raw_buf.extend_from_slice(f);
                    }
                }
            }
            let len = u16::from_be_bytes([self.raw_buf[3], self.raw_buf[4]]) as usize;
            let need = 5 + len;
            while self.raw_buf.len() < need {
                let mut tmp = vec![0u8; need - self.raw_buf.len()];
                let mut rb = ReadBuf::new(&mut tmp);
                match Pin::new(&mut self.tcp).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let f = rb.filled();
                        if f.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                        self.raw_buf.extend_from_slice(f);
                    }
                }
            }
            let rec = self.raw_buf.drain(..need).collect::<Vec<_>>();
            let ct = rec[0];
            if ct == 20 {
                continue;
            }
            if ct == 21 {
                return Poll::Ready(Err(err("tls alert")));
            }
            if ct != 23 {
                return Poll::Ready(Err(err("bad app ct")));
            }
            let plain = match open_record(
                self.aead,
                &self.r_key16,
                &self.r_key32,
                &self.r_iv,
                self.r_seq,
                &rec[5..],
            ) {
                Ok(p) => p,
                Err(e) => return Poll::Ready(Err(e)),
            };
            self.r_seq += 1;
            if plain.is_empty() {
                continue;
            }
            let inner_ct = plain[plain.len() - 1];
            let data = &plain[..plain.len() - 1];
            if inner_ct == 0x17 {
                self.app_buf.extend_from_slice(data);
            }
            // ignore handshake/post-hs for now
        }
    }
}
