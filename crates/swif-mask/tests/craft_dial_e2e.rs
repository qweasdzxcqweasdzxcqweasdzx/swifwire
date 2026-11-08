//! Craft dial must complete TLS 1.3 against a rustls acceptor (edge-compatible).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use swif_mask::{
    accept_tls, dial_tls_craft, craft_dial_wired, tls_extension_order_ready_for, LabTlsMaterial,
    ClientHelloProfile, TlsVerifyMode,
};

#[tokio::test]
async fn craft_dial_handshake_and_echo() {
    assert!(craft_dial_wired());
    assert!(tls_extension_order_ready_for(ClientHelloProfile::ChromeStable));

    let material = LabTlsMaterial::generate("cover.local").unwrap();
    let acceptor = Arc::new(material.acceptor().unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let acc = acceptor.clone();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = accept_tls(tcp, &acc).await.expect("server accept");
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.expect("server read");
        assert_eq!(&buf[..n], b"ping-craft");
        tls.write_all(b"pong-craft").await.unwrap();
    });

    let mut client = dial_tls_craft(addr, &material, TlsVerifyMode::Pin)
        .await
        .expect("craft dial");
    assert!(!client.ja3_string.is_empty());
    // Let server finish accept; drain NST so read_seq matches app records.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    client.drain_post_handshake().await;
    client.write_all(b"ping-craft").await.expect("client write");
    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).await.expect("client read");
    assert_eq!(&buf[..n], b"pong-craft");
    server.await.unwrap();
}
