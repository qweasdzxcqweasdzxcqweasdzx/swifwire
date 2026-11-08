//! Load canonical vectors from repo `tests/vectors/`.

use std::path::PathBuf;

use swif_crypto::{derive_session_keys, open_record, seal_record, AeadKey, NonceSalt};
use swif_wire::RecordHdr;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors")
}

#[test]
fn aead_record_matches_vector() {
    let path = vectors_dir().join("aead_record_v0.hex");
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing {}: {e}", path.display()))
        .trim()
        .to_string();
    let key = AeadKey([0x11; 32]);
    let salt = NonceSalt([0x01, 0x02, 0x03, 0x04]);
    let sealed = seal_record(&key, salt, 0, RecordHdr::v0(), b"hello-frame").unwrap();
    assert_eq!(hex::encode(&sealed), expected);
    let (hdr, pt, n) = open_record(&key, salt, 0, &sealed).unwrap();
    assert_eq!(n, sealed.len());
    assert_eq!(hdr.encode() & 0xf0, 0);
    assert_eq!(pt, b"hello-frame");
}

#[test]
fn kdf_session_matches_vector() {
    let path = vectors_dir().join("kdf_session_v0.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let shared = v["shared_ascii"].as_str().unwrap().as_bytes();
    let tr = v["transcript_ascii"].as_str().unwrap().as_bytes();
    assert_eq!(shared.len(), 32);
    assert_eq!(tr.len(), 32);
    let keys = derive_session_keys(shared, tr);
    assert_eq!(hex::encode(keys.k_c2s.0), v["k_c2s_hex"].as_str().unwrap());
    assert_eq!(hex::encode(keys.k_s2c.0), v["k_s2c_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(keys.nonce_salt_c2s.0),
        v["nonce_salt_c2s_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(keys.nonce_salt_s2c.0),
        v["nonce_salt_s2c_hex"].as_str().unwrap()
    );
}
