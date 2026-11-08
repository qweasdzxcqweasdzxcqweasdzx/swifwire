//! Hard negative / stress tests for SwifHS v0 (protocol+core 0.5).

use std::sync::{Arc, Mutex};
use std::thread;

use swif_crypto::{StaticKeypair, TicketReplayWindow};
use swif_session::{
    client_finish_keys, client_finish_keys_ex, client_hello_inner, client_resume_hello,
    client_resume_hello_mode, server_hello_ticket, server_respond_keys, server_respond_keys_ex,
    server_respond_keys_ex_replay, ResumeMode, SessionTransport,
};
use swif_shape::{Shaper, ShaperProfile};
use swif_wire::{bodies, PROTOCOL_VERSION};

#[test]
fn rejects_wrong_protocol_version() {
    let server = StaticKeypair::generate();
    let (mut cr, _eph) = client_hello_inner(server.public_bytes(), 0x07);
    // Corrupt version nibble in inner header (bytes 4..6 after MAGIC).
    assert_eq!(&cr[0..4], b"SWI1");
    let ver = PROTOCOL_VERSION.wrapping_add(1);
    cr[4..6].copy_from_slice(&ver.to_be_bytes());
    assert!(server_respond_keys(&server, &cr, 0x07).is_err());
}

#[test]
fn rejects_bad_magic() {
    let server = StaticKeypair::generate();
    let (mut cr, _) = client_hello_inner(server.public_bytes(), 0x07);
    cr[0] = b'X';
    assert!(server_respond_keys(&server, &cr, 0x07).is_err());
}

#[test]
fn unknown_caps_soft_complete() {
    let server = StaticKeypair::generate();
    let (cr, eph) = client_hello_inner(server.public_bytes(), 0xffff_ffff_ffff_ffff);
    let (sr, ks) = server_respond_keys(&server, &cr, 0x07).unwrap();
    let kc = client_finish_keys(server.public_bytes(), &eph, &cr, &sr).unwrap();
    let mut c = SessionTransport::new_client(kc, Shaper::new(ShaperProfile::desktop()));
    let mut s = SessionTransport::new_server(ks, Shaper::new(ShaperProfile::desktop()));
    let f = bodies::stream_data(1, b"ok");
    assert_eq!(s.open_frame(&c.seal_frame(&f).unwrap()).unwrap().0, f);
}

#[test]
fn no_aead_before_keys_wrong_peer() {
    let a = StaticKeypair::generate();
    let b = StaticKeypair::generate();
    let (cr, eph) = client_hello_inner(a.public_bytes(), 0x07);
    let (sr, ks_a) = server_respond_keys(&a, &cr, 0x07).unwrap();
    let kc = client_finish_keys(a.public_bytes(), &eph, &cr, &sr).unwrap();
    let (cr2, _) = client_hello_inner(b.public_bytes(), 0x07);
    let (_sr2, ks_b) = server_respond_keys(&b, &cr2, 0x07).unwrap();
    let mut c = SessionTransport::new_client(kc, Shaper::new(ShaperProfile::desktop()));
    let mut s_bad = SessionTransport::new_server(ks_b, Shaper::new(ShaperProfile::desktop()));
    let wire = c.seal_frame(&bodies::stream_data(1, b"x")).unwrap();
    assert!(s_bad.open_frame(&wire).is_err());
    let mut s_ok = SessionTransport::new_server(ks_a, Shaper::new(ShaperProfile::desktop()));
    assert!(s_ok.open_frame(&wire).is_ok());
}

#[test]
fn stress_rekey_and_resume_parallel() {
    let server = Arc::new(StaticKeypair::generate());
    let master = server.public_bytes();
    let mut handles = Vec::new();
    for t in 0..8 {
        let server = server.clone();
        handles.push(thread::spawn(move || {
            for i in 0..32 {
                let (cr, eph) = client_hello_inner(server.public_bytes(), 0x07);
                let (sr, ks) = server_respond_keys(&server, &cr, 0x07).unwrap();
                let kc = client_finish_keys(server.public_bytes(), &eph, &cr, &sr).unwrap();
                let mut c = SessionTransport::new_client(kc, Shaper::new(ShaperProfile::desktop()));
                let mut s = SessionTransport::new_server(ks, Shaper::new(ShaperProfile::desktop()));
                let epoch = 1u64;
                let offer = c.seal_frame(&swif_wire::rekey(epoch)).unwrap();
                let (of, _) = s.open_frame(&offer).unwrap();
                assert!(swif_wire::parse_rekey(&swif_wire::parse_ctrl(&of).unwrap().1) == Some(epoch));
                let ack = s.seal_frame(&swif_wire::rekey(epoch)).unwrap();
                s.advance_rekey(epoch).unwrap();
                let (af, _) = c.open_frame(&ack).unwrap();
                assert!(swif_wire::parse_rekey(&swif_wire::parse_ctrl(&af).unwrap().1) == Some(epoch));
                c.advance_rekey(epoch).unwrap();
                let f = bodies::stream_data(1, format!("t{t}-{i}").as_bytes());
                assert_eq!(s.open_frame(&c.seal_frame(&f).unwrap()).unwrap().0, f);
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // resume_fast + resume_fs under shared replay window
    let (c1, eph1) = client_hello_inner(server.public_bytes(), 0x07);
    let (s1, _, _) = server_respond_keys_ex(&server, &master, &c1, 0x07).unwrap();
    let (_, psk) = client_finish_keys_ex(server.public_bytes(), &eph1, &c1, &s1).unwrap();
    let ticket = server_hello_ticket(&s1).unwrap();
    let win = Arc::new(Mutex::new(TicketReplayWindow::new(256)));
    let rh_fast = client_resume_hello(&ticket, &psk, 0x07);
    assert!(server_respond_keys_ex_replay(
        &server,
        &master,
        &rh_fast,
        0x07,
        Some(&mut *win.lock().unwrap())
    )
    .is_ok());
    assert!(server_respond_keys_ex_replay(
        &server,
        &master,
        &rh_fast,
        0x07,
        Some(&mut *win.lock().unwrap())
    )
    .is_err());

    let (c2, eph2) = client_hello_inner(server.public_bytes(), 0x07);
    let (s2, _, _) = server_respond_keys_ex(&server, &master, &c2, 0x07).unwrap();
    let (_, psk2) = client_finish_keys_ex(server.public_bytes(), &eph2, &c2, &s2).unwrap();
    let ticket2 = server_hello_ticket(&s2).unwrap();
    let (rh_fs, _) = client_resume_hello_mode(&ticket2, &psk2, 0x07, ResumeMode::Fs);
    assert!(server_respond_keys_ex_replay(
        &server,
        &master,
        &rh_fs,
        0x07,
        Some(&mut *win.lock().unwrap())
    )
    .is_ok());
}
