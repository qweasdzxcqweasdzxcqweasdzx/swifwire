fn main() {
    use swif_crypto::{seal_record, AeadKey, NonceSalt, derive_session_keys};
    use swif_wire::RecordHdr;
    let key = AeadKey([0x11; 32]);
    let salt = NonceSalt([0x01, 0x02, 0x03, 0x04]);
    let sealed = seal_record(&key, salt, 0, RecordHdr::v0(), b"hello-frame").unwrap();
    println!("AEAD={}", hex::encode(&sealed));
    // Both inputs must be exactly 32 ASCII bytes (canonical vector contract).
    let shared = b"shared-secret-32-bytes-pad!!!!!!"; // 32
    let tr = b"transcript-fixed-bytes!!!!!!!!!!"; // 32
    assert_eq!(shared.len(), 32);
    assert_eq!(tr.len(), 32);
    let keys = derive_session_keys(shared, tr);
    println!("shared={}", std::str::from_utf8(shared).unwrap());
    println!("tr={}", std::str::from_utf8(tr).unwrap());
    println!("C2S={}", hex::encode(keys.k_c2s.0));
    println!("S2C={}", hex::encode(keys.k_s2c.0));
    println!("NSC={}", hex::encode(keys.nonce_salt_c2s.0));
    println!("NSS={}", hex::encode(keys.nonce_salt_s2c.0));
}
