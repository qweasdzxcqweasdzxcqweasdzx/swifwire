//! SwifHS v0 — 1-RTT static-DH handshake + ticket resume (X25519 + SHA-256 proofs).
//!
//! Not Noise_IK / `snow`. Wire layout frozen as SwifHS v0 (see docs/WIRE.md §4).
//! Noise_IK migration requires PROTOCOL_VERSION bump.

use rand::RngCore;
use sha2::{Digest, Sha256};
use swif_crypto::{
    derive_session_keys, open_ticket, public_from_bytes, seal_ticket, ticket_expired,
    EphemeralKeypair, SessionKeys, StaticKeypair,
};
use swif_wire::{MAGIC_INNER, PROTOCOL_VERSION};

use crate::error::{Error, Result};

const TICKET_TTL_SECS: u64 = 24 * 3600;

/// Ticket resume policy (explicit; DESIGN §C.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ResumeMode {
    /// Current lab/prod: eph_pub = 0, keys from ticket PSK only (no FS).
    #[default]
    Fast,
    /// Fresh client+server ephemeral mixed with PSK (forward secrecy on resume).
    Fs,
}

#[derive(Clone, Copy, Debug)]
pub enum HandshakeRole {
    Client,
    Server,
}

#[derive(Debug, Clone)]
pub struct ClientHelloInner {
    pub eph_pub: [u8; 32],
    pub static_proof: [u8; 32],
    pub caps: u64,
    pub ticket: Vec<u8>,
    pub pad: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ServerHelloInner {
    pub eph_pub: [u8; 32],
    pub static_proof: [u8; 32],
    pub caps: u64,
    pub ticket: Vec<u8>,
    pub pad: Vec<u8>,
}

fn encode_client(ch: &ClientHelloInner) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&MAGIC_INNER);
    o.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    o.extend_from_slice(&ch.eph_pub);
    o.extend_from_slice(&ch.static_proof);
    o.extend_from_slice(&ch.caps.to_be_bytes());
    o.extend_from_slice(&(ch.ticket.len() as u16).to_be_bytes());
    o.extend_from_slice(&ch.ticket);
    o.extend_from_slice(&(ch.pad.len() as u16).to_be_bytes());
    o.extend_from_slice(&ch.pad);
    o
}

fn decode_client(buf: &[u8]) -> Result<ClientHelloInner> {
    if buf.len() < 4 + 2 + 32 + 32 + 8 + 2 {
        return Err(Error::Handshake);
    }
    if buf[0..4] != MAGIC_INNER {
        return Err(Error::BadMagic);
    }
    let ver = u16::from_be_bytes([buf[4], buf[5]]);
    if ver != PROTOCOL_VERSION {
        return Err(Error::Version);
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&buf[6..38]);
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&buf[38..70]);
    let caps = u64::from_be_bytes(buf[70..78].try_into().unwrap());
    let mut i = 78;
    let tlen = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;
    if buf.len() < i + tlen + 2 {
        return Err(Error::Handshake);
    }
    let ticket = buf[i..i + tlen].to_vec();
    i += tlen;
    let plen = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;
    if buf.len() < i + plen {
        return Err(Error::Handshake);
    }
    Ok(ClientHelloInner {
        eph_pub: eph,
        static_proof: proof,
        caps,
        ticket,
        pad: buf[i..i + plen].to_vec(),
    })
}

fn encode_server(sh: &ServerHelloInner) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    o.extend_from_slice(&sh.eph_pub);
    o.extend_from_slice(&sh.static_proof);
    o.extend_from_slice(&sh.caps.to_be_bytes());
    o.extend_from_slice(&(sh.ticket.len() as u16).to_be_bytes());
    o.extend_from_slice(&sh.ticket);
    o.extend_from_slice(&(sh.pad.len() as u16).to_be_bytes());
    o.extend_from_slice(&sh.pad);
    o
}

fn decode_server(buf: &[u8]) -> Result<ServerHelloInner> {
    if buf.len() < 2 + 32 + 32 + 8 + 2 {
        return Err(Error::Handshake);
    }
    let ver = u16::from_be_bytes([buf[0], buf[1]]);
    if ver != PROTOCOL_VERSION {
        return Err(Error::Version);
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&buf[2..34]);
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&buf[34..66]);
    let caps = u64::from_be_bytes(buf[66..74].try_into().unwrap());
    let mut i = 74;
    let tlen = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;
    if buf.len() < i + tlen + 2 {
        return Err(Error::Handshake);
    }
    let ticket = buf[i..i + tlen].to_vec();
    i += tlen;
    let plen = u16::from_be_bytes([buf[i], buf[i + 1]]) as usize;
    i += 2;
    if buf.len() < i + plen {
        return Err(Error::Handshake);
    }
    Ok(ServerHelloInner {
        eph_pub: eph,
        static_proof: proof,
        caps,
        ticket,
        pad: buf[i..i + plen].to_vec(),
    })
}

fn proof(shared: &[u8], label: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(shared);
    h.update(label);
    h.finalize().into()
}

fn transcript(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn random_pad(max: usize) -> Vec<u8> {
    let n = (rand::random::<u16>() as usize) % (max.max(1));
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resume PSK derived from DH shared (client+server both compute after full HS).
pub fn resume_psk_from_shared(shared: &[u8]) -> [u8; 32] {
    proof(shared, b"ticket-secret")
}

fn issue_ticket(ticket_master: &[u8; 32], secret: &[u8; 32]) -> Result<Vec<u8>> {
    let exp = now_unix().saturating_add(TICKET_TTL_SECS);
    seal_ticket(ticket_master, secret, exp).map_err(|_| Error::Handshake)
}

/// Client builds hello knowing server static public.
pub fn client_hello_inner(server_static_pub: [u8; 32], caps: u64) -> (Vec<u8>, EphemeralKeypair) {
    let eph = EphemeralKeypair::generate();
    let server_pub = public_from_bytes(server_static_pub);
    let es = eph.diffie_hellman(&server_pub);
    let ch = ClientHelloInner {
        eph_pub: eph.public.to_bytes(),
        static_proof: proof(es.as_bytes(), b"client-es"),
        caps,
        ticket: Vec::new(),
        pad: random_pad(64),
    };
    (encode_client(&ch), eph)
}

/// Resume hello (`ResumeMode::Fast`): sealed ticket + proof under resume PSK; eph = 0.
pub fn client_resume_hello(ticket_blob: &[u8], resume_psk: &[u8; 32], caps: u64) -> Vec<u8> {
    client_resume_hello_mode(ticket_blob, resume_psk, caps, ResumeMode::Fast)
        .0
}

/// Resume hello with explicit mode. `Fs` returns fresh ephemeral for `client_finish_resume_fs`.
pub fn client_resume_hello_mode(
    ticket_blob: &[u8],
    resume_psk: &[u8; 32],
    caps: u64,
    mode: ResumeMode,
) -> (Vec<u8>, Option<EphemeralKeypair>) {
    match mode {
        ResumeMode::Fast => {
            let ch = ClientHelloInner {
                eph_pub: [0u8; 32],
                static_proof: proof(resume_psk, b"client-resume"),
                caps,
                ticket: ticket_blob.to_vec(),
                pad: random_pad(32),
            };
            (encode_client(&ch), None)
        }
        ResumeMode::Fs => {
            let eph = EphemeralKeypair::generate();
            let ch = ClientHelloInner {
                eph_pub: eph.public.to_bytes(),
                static_proof: proof(resume_psk, b"client-resume-fs"),
                caps,
                ticket: ticket_blob.to_vec(),
                pad: random_pad(48),
            };
            (encode_client(&ch), Some(eph))
        }
    }
}

/// Server validates client hello; full HS or ticket resume.
pub fn server_respond_keys(
    server_static: &StaticKeypair,
    client_raw: &[u8],
    caps: u64,
) -> Result<(Vec<u8>, SessionKeys)> {
    let master = server_static.public_bytes();
    let (raw, keys, _) = server_respond_keys_ex(server_static, &master, client_raw, caps)?;
    Ok((raw, keys))
}

/// Extended: custom ticket master + resume flag.
pub fn server_respond_keys_ex(
    server_static: &StaticKeypair,
    ticket_master: &[u8; 32],
    client_raw: &[u8],
    caps: u64,
) -> Result<(Vec<u8>, SessionKeys, bool)> {
    let ch = decode_client(client_raw)?;

    if !ch.ticket.is_empty() {
        let (secret, exp) = open_ticket(ticket_master, &ch.ticket).map_err(|_| Error::Handshake)?;
        if ticket_expired(exp, now_unix()) {
            return Err(Error::Handshake);
        }
        // Fast resume: sentinel zero eph.
        if ch.eph_pub == [0u8; 32] {
            if proof(&secret, b"client-resume") != ch.static_proof {
                return Err(Error::Handshake);
            }
            let new_ticket = issue_ticket(ticket_master, &secret)?;
            let sh = ServerHelloInner {
                eph_pub: [0u8; 32],
                static_proof: proof(&secret, b"server-resume"),
                caps,
                ticket: new_ticket,
                pad: random_pad(32),
            };
            let server_raw = encode_server(&sh);
            let tr = transcript(&[client_raw, &server_raw]);
            let keys = derive_session_keys(&secret, &tr);
            return Ok((server_raw, keys, true));
        }
        // Fs resume: fresh ee mixed with ticket PSK.
        if proof(&secret, b"client-resume-fs") != ch.static_proof {
            return Err(Error::Handshake);
        }
        let client_eph = public_from_bytes(ch.eph_pub);
        let eph = EphemeralKeypair::generate();
        let ee = eph.diffie_hellman(&client_eph);
        let mut shared = [0u8; 64];
        shared[..32].copy_from_slice(&secret);
        shared[32..].copy_from_slice(ee.as_bytes());
        let new_ticket = issue_ticket(ticket_master, &secret)?;
        let sh = ServerHelloInner {
            eph_pub: eph.public.to_bytes(),
            static_proof: proof(ee.as_bytes(), b"server-resume-fs"),
            caps,
            ticket: new_ticket,
            pad: random_pad(48),
        };
        let server_raw = encode_server(&sh);
        let tr = transcript(&[client_raw, &server_raw]);
        let keys = derive_session_keys(&shared, &tr);
        return Ok((server_raw, keys, true));
    }

    let client_eph = public_from_bytes(ch.eph_pub);
    let es = server_static.diffie_hellman(&client_eph);
    if proof(es.as_bytes(), b"client-es") != ch.static_proof {
        return Err(Error::Handshake);
    }
    let eph = EphemeralKeypair::generate();
    let ee = eph.diffie_hellman(&client_eph);
    let mut shared = [0u8; 64];
    shared[..32].copy_from_slice(es.as_bytes());
    shared[32..].copy_from_slice(ee.as_bytes());

    let psk = resume_psk_from_shared(&shared);
    let ticket = issue_ticket(ticket_master, &psk)?;
    let sh = ServerHelloInner {
        eph_pub: eph.public.to_bytes(),
        static_proof: proof(ee.as_bytes(), b"server-ee"),
        caps,
        ticket,
        pad: random_pad(64),
    };
    let server_raw = encode_server(&sh);
    let tr = transcript(&[client_raw, &server_raw]);
    let keys = derive_session_keys(&shared, &tr);
    Ok((server_raw, keys, false))
}

/// Client finishes after server hello (full HS). Returns keys + resume PSK to store with ticket.
pub fn client_finish_keys(
    server_static_pub: [u8; 32],
    client_eph: &EphemeralKeypair,
    client_raw: &[u8],
    server_raw: &[u8],
) -> Result<SessionKeys> {
    let (keys, _) = client_finish_keys_ex(server_static_pub, client_eph, client_raw, server_raw)?;
    Ok(keys)
}

pub fn client_finish_keys_ex(
    server_static_pub: [u8; 32],
    client_eph: &EphemeralKeypair,
    client_raw: &[u8],
    server_raw: &[u8],
) -> Result<(SessionKeys, [u8; 32])> {
    let sh = decode_server(server_raw)?;
    let server_pub = public_from_bytes(server_static_pub);
    let es = client_eph.diffie_hellman(&server_pub);
    let server_eph = public_from_bytes(sh.eph_pub);
    let ee = client_eph.diffie_hellman(&server_eph);
    if proof(ee.as_bytes(), b"server-ee") != sh.static_proof {
        return Err(Error::Handshake);
    }
    let mut shared = [0u8; 64];
    shared[..32].copy_from_slice(es.as_bytes());
    shared[32..].copy_from_slice(ee.as_bytes());
    let tr = transcript(&[client_raw, server_raw]);
    let keys = derive_session_keys(&shared, &tr);
    let psk = resume_psk_from_shared(&shared);
    Ok((keys, psk))
}

/// Client finishes `ResumeMode::Fast`. Returns keys + refreshed ticket blob.
pub fn client_finish_resume(
    resume_psk: &[u8; 32],
    client_raw: &[u8],
    server_raw: &[u8],
) -> Result<(SessionKeys, Vec<u8>)> {
    let sh = decode_server(server_raw)?;
    if proof(resume_psk, b"server-resume") != sh.static_proof {
        return Err(Error::Handshake);
    }
    let tr = transcript(&[client_raw, server_raw]);
    let keys = derive_session_keys(resume_psk, &tr);
    Ok((keys, sh.ticket))
}

/// Client finishes `ResumeMode::Fs` (needs client ephemeral from hello).
pub fn client_finish_resume_fs(
    resume_psk: &[u8; 32],
    client_eph: &EphemeralKeypair,
    client_raw: &[u8],
    server_raw: &[u8],
) -> Result<(SessionKeys, Vec<u8>)> {
    let sh = decode_server(server_raw)?;
    let server_eph = public_from_bytes(sh.eph_pub);
    let ee = client_eph.diffie_hellman(&server_eph);
    if proof(ee.as_bytes(), b"server-resume-fs") != sh.static_proof {
        return Err(Error::Handshake);
    }
    let mut shared = [0u8; 64];
    shared[..32].copy_from_slice(resume_psk);
    shared[32..].copy_from_slice(ee.as_bytes());
    let tr = transcript(&[client_raw, server_raw]);
    let keys = derive_session_keys(&shared, &tr);
    Ok((keys, sh.ticket))
}

pub fn server_hello_ticket(server_raw: &[u8]) -> Result<Vec<u8>> {
    Ok(decode_server(server_raw)?.ticket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_agrees() {
        let server = StaticKeypair::generate();
        let (client_raw, eph) = client_hello_inner(server.public_bytes(), 0x7);
        let (server_raw, keys_s) =
            server_respond_keys(&server, &client_raw, 0x7).expect("server hs");
        let keys_c =
            client_finish_keys(server.public_bytes(), &eph, &client_raw, &server_raw).unwrap();
        assert_eq!(keys_c.k_c2s.0, keys_s.k_c2s.0);
        assert_eq!(keys_c.k_s2c.0, keys_s.k_s2c.0);
        assert!(!server_hello_ticket(&server_raw).unwrap().is_empty());
    }

    #[test]
    fn ticket_resume_under_2s() {
        let server = StaticKeypair::generate();
        let master = server.public_bytes();

        let (client_raw, eph) = client_hello_inner(server.public_bytes(), 0x7);
        let (server_raw, _keys_s, _) =
            server_respond_keys_ex(&server, &master, &client_raw, 0x7).unwrap();
        let (_keys_c, psk) =
            client_finish_keys_ex(server.public_bytes(), &eph, &client_raw, &server_raw).unwrap();
        let ticket = server_hello_ticket(&server_raw).unwrap();

        let t0 = std::time::Instant::now();
        let resume_hello = client_resume_hello(&ticket, &psk, 0x7);
        let (server_raw2, keys_s2, is_resume) =
            server_respond_keys_ex(&server, &master, &resume_hello, 0x7).unwrap();
        assert!(is_resume);
        let (keys_c2, _new_ticket) =
            client_finish_resume(&psk, &resume_hello, &server_raw2).unwrap();
        assert_eq!(keys_c2.k_c2s.0, keys_s2.k_c2s.0);
        assert!(t0.elapsed().as_millis() < 2000);
    }

    #[test]
    fn ticket_resume_fs_agrees() {
        let server = StaticKeypair::generate();
        let master = server.public_bytes();
        let (c1, eph) = client_hello_inner(server.public_bytes(), 0x7);
        let (s1, _, _) = server_respond_keys_ex(&server, &master, &c1, 0x7).unwrap();
        let (_, psk) = client_finish_keys_ex(server.public_bytes(), &eph, &c1, &s1).unwrap();
        let ticket = server_hello_ticket(&s1).unwrap();

        let (rh, eph_r) = client_resume_hello_mode(&ticket, &psk, 0x7, ResumeMode::Fs);
        let eph_r = eph_r.expect("fs eph");
        let (sr, keys_s, resumed) = server_respond_keys_ex(&server, &master, &rh, 0x7).unwrap();
        assert!(resumed);
        let (keys_c, _) = client_finish_resume_fs(&psk, &eph_r, &rh, &sr).unwrap();
        assert_eq!(keys_c.k_c2s.0, keys_s.k_c2s.0);
    }

    #[test]
    fn wrong_server_key_fails() {
        let server = StaticKeypair::generate();
        let other = StaticKeypair::generate();
        let (client_raw, _) = client_hello_inner(server.public_bytes(), 0x7);
        // Cover path: wrong static cannot satisfy client-es proof.
        assert!(server_respond_keys(&other, &client_raw, 0x7).is_err());
    }

    #[test]
    fn wrong_ticket_proof_fails() {
        let server = StaticKeypair::generate();
        let master = server.public_bytes();
        let (c1, eph) = client_hello_inner(server.public_bytes(), 0x7);
        let (s1, _, _) = server_respond_keys_ex(&server, &master, &c1, 0x7).unwrap();
        let (_, psk) = client_finish_keys_ex(server.public_bytes(), &eph, &c1, &s1).unwrap();
        let ticket = server_hello_ticket(&s1).unwrap();
        let bad_psk = [9u8; 32];
        let rh = client_resume_hello(&ticket, &bad_psk, 0x7);
        assert!(server_respond_keys_ex(&server, &master, &rh, 0x7).is_err());
        let _ = psk;
    }
}
