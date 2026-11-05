//! Reconnect harness: full HS → ticket resume timed.

#[cfg(test)]
mod tests {
    use crate::handshake::{
        client_finish_keys_ex, client_finish_resume, client_hello_inner, client_resume_hello,
        server_hello_ticket, server_respond_keys_ex,
    };
    use swif_crypto::StaticKeypair;
    use std::time::Instant;

    #[test]
    fn reconnect_suite_resume_under_2s() {
        let server = StaticKeypair::generate();
        let master = server.public_bytes();

        // Session 1
        let (c1, eph) = client_hello_inner(server.public_bytes(), 0x07);
        let (s1, _, _) = server_respond_keys_ex(&server, &master, &c1, 0x07).unwrap();
        let (_k, psk) = client_finish_keys_ex(server.public_bytes(), &eph, &c1, &s1).unwrap();
        let ticket = server_hello_ticket(&s1).unwrap();

        // Network change → resume
        let t0 = Instant::now();
        for _ in 0..5 {
            let rh = client_resume_hello(&ticket, &psk, 0x07);
            let (sr, keys_s, resumed) =
                server_respond_keys_ex(&server, &master, &rh, 0x07).unwrap();
            assert!(resumed);
            let (keys_c, _) = client_finish_resume(&psk, &rh, &sr).unwrap();
            assert_eq!(keys_c.k_c2s.0, keys_s.k_c2s.0);
        }
        assert!(
            t0.elapsed().as_millis() < 2000,
            "5 resumes took {:?}",
            t0.elapsed()
        );
    }
}
