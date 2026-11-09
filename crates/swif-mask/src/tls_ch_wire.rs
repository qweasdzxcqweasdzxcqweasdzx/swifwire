//! Pack-driven TLS 1.3 ClientHello **wire** builder (0.5).
//!
//! Lab digests use deterministic shares; live craft dial supplies real random + X25519.

use sha2::{Digest, Sha256};

use crate::tls_fingerprint::intended_extension_order;
use crate::tls_profile::{ClientHelloProfile, TlsPackHints};
use crate::tls_provider::suite_order_ids;

fn suite_iana_ids(profile: ClientHelloProfile) -> Vec<u16> {
    suite_order_ids(profile)
        .into_iter()
        .filter_map(|name| match name {
            "TLS13_AES_128_GCM_SHA256" => Some(0x1301),
            "TLS13_AES_256_GCM" | "TLS13_AES_256_GCM_SHA384" => Some(0x1302),
            "TLS13_CHACHA20" | "TLS13_CHACHA20_POLY1305_SHA256" => Some(0x1303),
            _ => None,
        })
        .collect()
}

/// Live handshake parameters (real entropy + X25519 share).
#[derive(Debug, Clone)]
pub struct LiveClientHelloParams {
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub key_share_x25519: [u8; 32],
    /// Skip ECH/ALPS/compress stubs that some stacks reject; keep pack order for the rest.
    pub omit_experimental: bool,
}

impl Default for LiveClientHelloParams {
    fn default() -> Self {
        Self {
            random: [0x11; 32],
            session_id: Vec::new(),
            key_share_x25519: [0x42; 32],
            omit_experimental: false,
        }
    }
}

/// Build one TLS record containing ClientHello (handshake type 1) — lab/deterministic.
pub fn build_client_hello_record(hints: &TlsPackHints, sni: &str) -> Vec<u8> {
    build_client_hello_record_live(hints, sni, &LiveClientHelloParams::default())
}

/// Live craft dial ClientHello with pack extension order.
pub fn build_client_hello_record_live(
    hints: &TlsPackHints,
    sni: &str,
    live: &LiveClientHelloParams,
) -> Vec<u8> {
    let ch = build_client_hello_body(hints, sni, live);
    let mut hs = Vec::with_capacity(4 + ch.len());
    hs.push(0x01); // client_hello
    hs.push(((ch.len() >> 16) & 0xff) as u8);
    hs.push(((ch.len() >> 8) & 0xff) as u8);
    hs.push((ch.len() & 0xff) as u8);
    hs.extend_from_slice(&ch);

    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(0x16); // handshake
    rec.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy record version
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn build_client_hello_body(hints: &TlsPackHints, sni: &str, live: &LiveClientHelloParams) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version TLS1.2
    body.extend_from_slice(&live.random);
    body.push(live.session_id.len() as u8);
    body.extend_from_slice(&live.session_id);

    let suites = suite_iana_ids(hints.profile);
    let mut suite_bytes = Vec::with_capacity(2 + suites.len() * 2);
    for id in &suites {
        suite_bytes.extend_from_slice(&id.to_be_bytes());
    }
    if hints.grease {
        let mut with_grease = Vec::with_capacity(2 + suite_bytes.len());
        with_grease.extend_from_slice(&0x0a0au16.to_be_bytes());
        with_grease.extend_from_slice(&suite_bytes);
        suite_bytes = with_grease;
    }
    body.extend_from_slice(&(suite_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&suite_bytes);

    body.push(1);
    body.push(0);

    let exts = build_extensions(hints, sni, live);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    body
}

fn build_extensions(hints: &TlsPackHints, sni: &str, live: &LiveClientHelloParams) -> Vec<u8> {
    let order = intended_extension_order(hints.profile);
    let mut out = Vec::new();
    let types: Vec<u16> = if order.is_empty() {
        vec![0x0000, 0x000a, 0x000d, 0x0010, 0x002b, 0x002d, 0x0033]
    } else {
        order.to_vec()
    };
    for ty in types {
        if live.omit_experimental && matches!(ty, 0x001b | 0x4469 | 0xfe0d) {
            continue;
        }
        append_ext(&mut out, ty, hints, sni, live);
    }
    if hints.grease {
        let mut greased = Vec::with_capacity(4 + out.len());
        greased.extend_from_slice(&0x0a0au16.to_be_bytes());
        greased.extend_from_slice(&0u16.to_be_bytes());
        greased.extend_from_slice(&out);
        return greased;
    }
    out
}

fn append_ext(
    out: &mut Vec<u8>,
    ty: u16,
    hints: &TlsPackHints,
    sni: &str,
    live: &LiveClientHelloParams,
) {
    let data = match ty {
        0x0000 => ext_sni(sni),
        0x0005 => vec![0x01, 0x00, 0x00, 0x00, 0x00],
        0x000a => ext_supported_groups(),
        0x000b => vec![0x01, 0x00],
        0x000d => ext_sig_algs(),
        0x0010 => ext_alpn(&hints.alpn),
        0x0012 => Vec::new(),
        0x0017 => Vec::new(),
        0x001b => vec![0x02, 0x00, 0x02],
        0x0023 => Vec::new(),
        0x002b => vec![0x02, 0x03, 0x04],
        0x002d => vec![0x01, 0x01],
        0x0033 => ext_key_share_live(&live.key_share_x25519),
        0x4469 => ext_alps(&hints.alpn),
        0xfe0d => vec![0x00],
        0xff01 => vec![0x00],
        _ => Vec::new(),
    };
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(&data);
}

fn ext_sni(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut d = Vec::with_capacity(5 + host.len());
    let list_len = (3 + host.len()) as u16;
    d.extend_from_slice(&list_len.to_be_bytes());
    d.push(0); // host_name
    d.extend_from_slice(&(host.len() as u16).to_be_bytes());
    d.extend_from_slice(host);
    d
}

fn ext_supported_groups() -> Vec<u8> {
    // x25519, secp256r1, secp384r1
    let groups: [u16; 3] = [0x001d, 0x0017, 0x0018];
    let mut d = Vec::with_capacity(2 + groups.len() * 2);
    d.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
    for g in groups {
        d.extend_from_slice(&g.to_be_bytes());
    }
    d
}

fn ext_sig_algs() -> Vec<u8> {
    let algs: [u16; 4] = [0x0403, 0x0804, 0x0401, 0x0503];
    let mut d = Vec::with_capacity(2 + algs.len() * 2);
    d.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
    for a in algs {
        d.extend_from_slice(&a.to_be_bytes());
    }
    d
}

fn ext_alpn(alpn: &[String]) -> Vec<u8> {
    let mut protocols = Vec::new();
    for p in alpn {
        let b = p.as_bytes();
        protocols.push(b.len() as u8);
        protocols.extend_from_slice(b);
    }
    let mut d = Vec::with_capacity(2 + protocols.len());
    d.extend_from_slice(&(protocols.len() as u16).to_be_bytes());
    d.extend_from_slice(&protocols);
    d
}

fn ext_key_share_live(pub_bytes: &[u8; 32]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(4 + 32);
    entry.extend_from_slice(&0x001du16.to_be_bytes());
    entry.extend_from_slice(&32u16.to_be_bytes());
    entry.extend_from_slice(pub_bytes);
    let mut d = Vec::with_capacity(2 + entry.len());
    d.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    d.extend_from_slice(&entry);
    d
}

fn ext_alps(alpn: &[String]) -> Vec<u8> {
    // Application settings — list ALPN ids (simplified).
    ext_alpn(alpn)
}

/// Extract IANA extension types from a crafted ClientHello record (for tests / JA3).
pub fn extension_types_from_record(rec: &[u8]) -> Option<Vec<u16>> {
    if rec.len() < 9 || rec[0] != 0x16 {
        return None;
    }
    let hs_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
    if rec.len() < 5 + hs_len || rec[5] != 0x01 {
        return None;
    }
    let body = &rec[9..5 + hs_len];
    if body.len() < 35 {
        return None;
    }
    let mut i = 34; // after version+random
    let sid_len = body[i] as usize;
    i += 1 + sid_len;
    if body.len() < i + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2 + cs_len;
    if body.len() < i + 1 {
        return None;
    }
    let comp_len = body[i] as usize;
    i += 1 + comp_len;
    if body.len() < i + 2 {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    if body.len() < i + ext_len {
        return None;
    }
    let exts = &body[i..i + ext_len];
    let mut types = Vec::new();
    let mut j = 0;
    while j + 4 <= exts.len() {
        let ty = u16::from_be_bytes([exts[j], exts[j + 1]]);
        let len = u16::from_be_bytes([exts[j + 2], exts[j + 3]]) as usize;
        types.push(ty);
        j += 4 + len;
    }
    Some(types)
}

/// Classic JA3 string over crafted ClientHello (not rustls wire).
pub fn ja3_string_from_record(rec: &[u8]) -> Option<String> {
    if rec.len() < 9 || rec[0] != 0x16 {
        return None;
    }
    let hs_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
    if rec.len() < 5 + hs_len {
        return None;
    }
    let body = &rec[9..5 + hs_len];
    if body.len() < 35 {
        return None;
    }
    let mut i = 34;
    let sid_len = body[i] as usize;
    i += 1 + sid_len;
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    let mut ciphers = Vec::new();
    let end_cs = i + cs_len;
    while i + 2 <= end_cs {
        ciphers.push(u16::from_be_bytes([body[i], body[i + 1]]).to_string());
        i += 2;
    }
    let comp_len = body[i] as usize;
    i += 1 + comp_len;
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    let exts = &body[i..i + ext_len];
    let mut ext_types = Vec::new();
    let mut groups = Vec::new();
    let mut sigs = Vec::new();
    let mut j = 0;
    while j + 4 <= exts.len() {
        let ty = u16::from_be_bytes([exts[j], exts[j + 1]]);
        let len = u16::from_be_bytes([exts[j + 2], exts[j + 3]]) as usize;
        let data = &exts[j + 4..j + 4 + len.min(exts.len() - (j + 4))];
        ext_types.push(ty.to_string());
        if ty == 0x000a && data.len() >= 2 {
            let gl = u16::from_be_bytes([data[0], data[1]]) as usize;
            let mut k = 2;
            while k + 2 <= 2 + gl && k + 2 <= data.len() {
                groups.push(u16::from_be_bytes([data[k], data[k + 1]]).to_string());
                k += 2;
            }
        }
        if ty == 0x000d && data.len() >= 2 {
            let sl = u16::from_be_bytes([data[0], data[1]]) as usize;
            let mut k = 2;
            while k + 2 <= 2 + sl && k + 2 <= data.len() {
                sigs.push(u16::from_be_bytes([data[k], data[k + 1]]).to_string());
                k += 2;
            }
        }
        j += 4 + len;
    }
    // JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    Some(format!(
        "771,{},{},{},0",
        ciphers.join("-"),
        ext_types.join("-"),
        groups.join("-")
    ))
}

pub fn ja3_hash_from_record(rec: &[u8]) -> Option<String> {
    let s = ja3_string_from_record(rec)?;
    let digest = Sha256::digest(s.as_bytes());
    // Classic JA3 uses MD5; we expose SHA-256 labeled digest to avoid MD5 dep, plus raw string.
    Some(hex::encode(digest))
}

/// JA4_a-style fingerprint over crafted ClientHello (lab corpus).
/// Format: `t13d{S}{E}{ALPN}_{ciphers_sorted}_{exts_sorted}_{sigalgs}`
/// Not guaranteed byte-identical to FoxIO JA4 of a real Chrome capture — pack drifts go here.
pub fn ja4_a_from_record(rec: &[u8]) -> Option<String> {
    if rec.len() < 9 || rec[0] != 0x16 {
        return None;
    }
    let hs_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
    if rec.len() < 5 + hs_len {
        return None;
    }
    let body = &rec[9..5 + hs_len];
    if body.len() < 35 {
        return None;
    }
    let mut i = 34;
    let sid_len = body[i] as usize;
    i += 1 + sid_len;
    let cs_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    let mut ciphers: Vec<u16> = Vec::new();
    let end_cs = i + cs_len;
    while i + 2 <= end_cs {
        ciphers.push(u16::from_be_bytes([body[i], body[i + 1]]));
        i += 2;
    }
    let comp_len = body[i] as usize;
    i += 1 + comp_len;
    let ext_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
    i += 2;
    let exts = &body[i..i + ext_len];
    let mut ext_types: Vec<u16> = Vec::new();
    let mut sigs: Vec<u16> = Vec::new();
    let mut alpn_first = "00".to_string();
    let mut j = 0;
    while j + 4 <= exts.len() {
        let ty = u16::from_be_bytes([exts[j], exts[j + 1]]);
        let len = u16::from_be_bytes([exts[j + 2], exts[j + 3]]) as usize;
        let data = &exts[j + 4..j + 4 + len.min(exts.len() - (j + 4))];
        if ty != 0x0029 {
            // exclude PSK from JA4_a sorted ext list (FoxIO convention)
            ext_types.push(ty);
        }
        if ty == 0x000d && data.len() >= 2 {
            let sl = u16::from_be_bytes([data[0], data[1]]) as usize;
            let mut k = 2;
            while k + 2 <= 2 + sl && k + 2 <= data.len() {
                sigs.push(u16::from_be_bytes([data[k], data[k + 1]]));
                k += 2;
            }
        }
        if ty == 0x0010 && data.len() >= 3 {
            let plen = data[2] as usize;
            if data.len() >= 3 + plen {
                let proto = std::str::from_utf8(&data[3..3 + plen]).unwrap_or("");
                alpn_first = if proto.is_empty() {
                    "00".into()
                } else if proto.len() >= 2 {
                    proto[..2].to_string()
                } else {
                    format!("{proto}0")
                };
            }
        }
        j += 4 + len;
    }
    let mut ciphers_s = ciphers.clone();
    ciphers_s.sort_unstable();
    let mut exts_s = ext_types.clone();
    exts_s.sort_unstable();
    let cipher_part = ciphers_s
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let ext_part = exts_s
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let sig_part = sigs
        .iter()
        .map(|s| format!("{s:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    Some(format!(
        "t13d{:02}{:02}{}_{}_{}_{}",
        ciphers.len().min(99),
        ext_types.len().min(99),
        alpn_first,
        cipher_part,
        ext_part,
        sig_part
    ))
}

pub fn craft_status_message() -> &'static str {
    "tls_ch_wire: pack-ordered ClientHello builder (lab + live params)"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls_fingerprint::intended_extension_order;

    #[test]
    fn chrome_extension_order_matches_intent() {
        let hints = TlsPackHints {
            profile: ClientHelloProfile::ChromeStable,
            grease: false,
            ..TlsPackHints::default()
        };
        let rec = build_client_hello_record(&hints, "cdn.example.com");
        let types = extension_types_from_record(&rec).unwrap();
        let intent: Vec<u16> = intended_extension_order(ClientHelloProfile::ChromeStable).to_vec();
        assert_eq!(types, intent);
    }

    #[test]
    fn ja3_string_stable() {
        let hints = TlsPackHints {
            profile: ClientHelloProfile::ChromeStable,
            grease: false,
            alpn: vec!["h2".into()],
            sni_pool_ref: None,
        };
        let rec = build_client_hello_record(&hints, "a.example");
        let a = ja3_string_from_record(&rec).unwrap();
        let b = ja3_string_from_record(&rec).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("771,"));
        assert!(ja3_hash_from_record(&rec).unwrap().len() == 64);
    }

    #[test]
    fn ja4_a_stable_and_starts_with_t13() {
        let hints = TlsPackHints {
            profile: ClientHelloProfile::ChromeStable,
            grease: false,
            alpn: vec!["h2".into(), "http/1.1".into()],
            sni_pool_ref: None,
        };
        let rec = build_client_hello_record(&hints, "cdn.example.com");
        let a = ja4_a_from_record(&rec).unwrap();
        let b = ja4_a_from_record(&rec).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("t13d"), "{a}");
    }
}
