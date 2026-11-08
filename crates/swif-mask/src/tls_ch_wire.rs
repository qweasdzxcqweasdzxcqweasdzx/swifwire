//! Pack-driven TLS 1.3 ClientHello **wire** builder (0.5).
//!
//! Produces a single TLS handshake record with browser-like **extension order**.
//! Used for JA3/JA4 lab digests and future dual-stack dial (`tls_ch_craft`).
//! Live `dial_tls` still uses rustls until craft dial is wired — status stays honest.

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

/// Build one TLS record containing ClientHello (handshake type 1).
pub fn build_client_hello_record(hints: &TlsPackHints, sni: &str) -> Vec<u8> {
    let ch = build_client_hello_body(hints, sni);
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

fn build_client_hello_body(hints: &TlsPackHints, sni: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(512);
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version TLS1.2
    body.extend_from_slice(&[0x11; 32]); // deterministic random for vectors
    body.push(0); // session_id empty

    let suites = suite_iana_ids(hints.profile);
    let mut suite_bytes = Vec::with_capacity(2 + suites.len() * 2);
    for id in &suites {
        suite_bytes.extend_from_slice(&id.to_be_bytes());
    }
    if hints.grease {
        // GREASE cipher 0x0a0a at front (Chrome-like).
        let mut with_grease = Vec::with_capacity(2 + suite_bytes.len());
        with_grease.extend_from_slice(&0x0a0au16.to_be_bytes());
        with_grease.extend_from_slice(&suite_bytes);
        suite_bytes = with_grease;
    }
    body.extend_from_slice(&(suite_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(&suite_bytes);

    body.push(1); // compression methods len
    body.push(0); // null

    let exts = build_extensions(hints, sni);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    body
}

fn build_extensions(hints: &TlsPackHints, sni: &str) -> Vec<u8> {
    let order = intended_extension_order(hints.profile);
    let mut out = Vec::new();
    if order.is_empty() {
        // rustls_default: minimal required TLS1.3 set
        for ty in [0x0000u16, 0x000a, 0x000d, 0x0010, 0x002b, 0x0033] {
            append_ext(&mut out, ty, hints, sni);
        }
        return out;
    }
    for &ty in order {
        append_ext(&mut out, ty, hints, sni);
    }
    if hints.grease {
        // Prepend GREASE extension type 0x0a0a with empty data (Chrome places GREASE in ext list).
        let mut greased = Vec::with_capacity(4 + out.len());
        greased.extend_from_slice(&0x0a0au16.to_be_bytes());
        greased.extend_from_slice(&0u16.to_be_bytes());
        greased.extend_from_slice(&out);
        return greased;
    }
    out
}

fn append_ext(out: &mut Vec<u8>, ty: u16, hints: &TlsPackHints, sni: &str) {
    let data = match ty {
        0x0000 => ext_sni(sni),
        0x0005 => vec![0x01, 0x00, 0x00, 0x00, 0x00], // status_request OCSP
        0x000a => ext_supported_groups(),
        0x000b => vec![0x01, 0x00], // ec_point_formats uncompressed
        0x000d => ext_sig_algs(),
        0x0010 => ext_alpn(&hints.alpn),
        0x0012 => Vec::new(), // SCT empty
        0x0017 => Vec::new(), // extended_master_secret
        0x001b => vec![0x02, 0x00, 0x02], // compress_certificate zlib
        0x0023 => Vec::new(), // session_ticket
        0x002b => vec![0x02, 0x03, 0x04], // supported_versions TLS1.3
        0x002d => vec![0x01, 0x01], // psk_ke_modes psk_dhe_ke
        0x0033 => ext_key_share(),
        0x4469 => ext_alps(&hints.alpn),
        0xfe0d => vec![0x00], // ECH stub (not real ECH)
        0xff01 => vec![0x00], // renegotiation_info
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

fn ext_key_share() -> Vec<u8> {
    // x25519 with deterministic 32-byte share (lab/fingerprint only — not a live HS key).
    let mut entry = Vec::with_capacity(4 + 32);
    entry.extend_from_slice(&0x001du16.to_be_bytes());
    entry.extend_from_slice(&32u16.to_be_bytes());
    entry.extend_from_slice(&[0x42; 32]);
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

/// True when crafted-CH path is selected for dial (env). Live dial not wired yet → always false.
pub fn tls_extension_order_ready() -> bool {
    // Reserve: SWIF_TLS_CH_CRAFT=1 will flip this once dial_tls_craft ships.
    false
}

pub fn craft_status_message() -> &'static str {
    "tls_ch_wire: ClientHello craft encoder ready for JA3 lab; dial_tls still rustls (extension_order=false)"
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
}
