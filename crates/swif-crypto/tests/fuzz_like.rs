//! Property-style corpus (0.5) — no cargo-fuzz required on Windows CI.

use swif_crypto::{
    derive_session_keys, open_record, seal_record, AeadKey, NonceSalt, TicketReplayWindow,
};
use swif_wire::RecordHdr;

#[test]
fn aead_wrong_key_always_fails() {
    let key = AeadKey([0x11; 32]);
    let bad = AeadKey([0x22; 32]);
    let salt = NonceSalt([1, 2, 3, 4]);
    for n in 0..64u64 {
        let pt = format!("frame-{n}");
        let sealed = seal_record(&key, salt, n, RecordHdr::v0(), pt.as_bytes()).unwrap();
        assert!(open_record(&bad, salt, n, &sealed).is_err());
        let (hdr, out, _) = open_record(&key, salt, n, &sealed).unwrap();
        assert_eq!(hdr.encode() & 0xf0, 0);
        assert_eq!(out, pt.as_bytes());
    }
}

#[test]
fn aead_bitflip_fails() {
    let key = AeadKey([0xab; 32]);
    let salt = NonceSalt([9, 8, 7, 6]);
    let mut sealed = seal_record(&key, salt, 0, RecordHdr::v0(), b"hello").unwrap();
    let i = sealed.len() / 2;
    sealed[i] ^= 0xff;
    assert!(open_record(&key, salt, 0, &sealed).is_err());
}

#[test]
fn kdf_deterministic_across_inputs() {
    for i in 0..32u8 {
        let mut shared = [0u8; 32];
        let mut tr = [0u8; 32];
        shared[0] = i;
        tr[31] = i;
        let a = derive_session_keys(&shared, &tr);
        let b = derive_session_keys(&shared, &tr);
        assert_eq!(a.k_c2s.0, b.k_c2s.0);
        assert_ne!(a.k_c2s.0, a.k_s2c.0);
    }
}

#[test]
fn ticket_replay_window_rejects_dupes() {
    let mut w = TicketReplayWindow::new(32);
    for i in 0..16u64 {
        let mut id = [0u8; 16];
        id[0] = i as u8;
        // false = first sight OK; true = replay
        assert!(!w.check_and_insert(&id), "first insert {i}");
        assert!(w.check_and_insert(&id), "replay {i}");
    }
}
