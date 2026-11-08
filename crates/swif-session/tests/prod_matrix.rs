//! Protocol readiness matrix for commercial / prod lab gate.

use swif_crypto::{StaticKeypair, TicketReplayWindow};
use swif_session::{
    client_finish_keys, client_finish_keys_ex, client_hello_inner, client_resume_hello,
    server_hello_ticket, server_respond_keys, server_respond_keys_ex,
    server_respond_keys_ex_replay, SessionTransport,
};
use swif_shape::{Shaper, ShaperProfile};
use swif_wire::bodies;

#[test]
fn matrix_handshake_rekey_resume_replay() {
    let server = StaticKeypair::generate();
    let master = server.public_bytes();

    // Fresh handshake + AEAD
    let (cr, eph) = client_hello_inner(server.public_bytes(), 0x07);
    let (sr, ks) = server_respond_keys(&server, &cr, 0x07).unwrap();
    let kc = client_finish_keys(server.public_bytes(), &eph, &cr, &sr).unwrap();
    let mut c = SessionTransport::new_client(kc, Shaper::new(ShaperProfile::desktop()));
    let mut s = SessionTransport::new_server(ks, Shaper::new(ShaperProfile::desktop()));
    let f = bodies::stream_data(1, b"matrix");
    let wire = c.seal_frame(&f).unwrap();
    assert_eq!(s.open_frame(&wire).unwrap().0, f);

    // REKEY ack-before-advance
    let epoch = 1u64;
    let offer = c.seal_frame(&swif_wire::rekey(epoch)).unwrap();
    let (of, _) = s.open_frame(&offer).unwrap();
    let (ty, p) = swif_wire::parse_ctrl(&of).unwrap();
    assert_eq!(ty, swif_wire::CtrlType::Rekey);
    assert_eq!(swif_wire::parse_rekey(&p), Some(epoch));
    let ack = s.seal_frame(&swif_wire::rekey(epoch)).unwrap();
    s.advance_rekey(epoch).unwrap();
    let (af, _) = c.open_frame(&ack).unwrap();
    assert_eq!(
        swif_wire::parse_rekey(&swif_wire::parse_ctrl(&af).unwrap().1),
        Some(epoch)
    );
    c.advance_rekey(epoch).unwrap();
    let f2 = bodies::stream_data(1, b"after");
    assert_eq!(s.open_frame(&c.seal_frame(&f2).unwrap()).unwrap().0, f2);

    // Ticket resume + replay reject
    let (c1, eph1) = client_hello_inner(server.public_bytes(), 0x07);
    let (s1, _, _) = server_respond_keys_ex(&server, &master, &c1, 0x07).unwrap();
    let (_, psk) = client_finish_keys_ex(server.public_bytes(), &eph1, &c1, &s1).unwrap();
    let ticket = server_hello_ticket(&s1).unwrap();
    let rh = client_resume_hello(&ticket, &psk, 0x07);
    let mut win = TicketReplayWindow::new(64);
    assert!(server_respond_keys_ex_replay(&server, &master, &rh, 0x07, Some(&mut win)).is_ok());
    assert!(server_respond_keys_ex_replay(&server, &master, &rh, 0x07, Some(&mut win)).is_err());
}
