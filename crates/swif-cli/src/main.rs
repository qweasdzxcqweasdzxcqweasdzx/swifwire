//! SwifWire CLI: local SOCKS5 → mask → edge.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;
use swif_crypto::StaticKeypair;
use swif_mask::{
    dial_tls, read_pref, write_pref, LabTlsMaterial, NullTcp, QuicFastClient, MaskDial,
};
use swif_mux::Mux;
use swif_session::{client_finish_keys, client_hello_inner, SessionTransport};
use swif_shape::{Shaper, ShaperProfile};
use swif_tun::{decode_udp4, encode_udp4, frame_to_tun, NullTun, TunDevice, TUN_ASSOC};
use swif_wire::FrameType;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9443")]
    server: SocketAddr,
    #[arg(long)]
    server_pub: Option<String>,
    #[arg(long, default_value = "server.pub")]
    pub_file: PathBuf,
    #[arg(long, default_value = "127.0.0.1:11080")]
    socks: SocketAddr,
    /// null_tcp | tls13_stable | quic_fast
    #[arg(long, default_value = "null_tcp")]
    mask: String,
    #[arg(long, default_value = "lab-cert.der.json")]
    tls_material: PathBuf,
    /// One-shot UDP map: e.g. 127.0.0.1:9 (discard) or echo service — exits after reply.
    #[arg(long)]
    udp_ping: Option<SocketAddr>,
    /// Lab TUN: inject one IPv4 packet via NullTun → edge L3 echo → verify.
    #[arg(long, default_value_t = false)]
    tun_smoke: bool,
    /// Open OS TUN (needs --features os-tun + wintun.dll + admin). Then runs NullTun smoke if unavailable.
    #[arg(long, default_value_t = false)]
    tun: bool,
}

fn load_pub(args: &Args) -> Result<[u8; 32]> {
    let hex_s = if let Some(h) = &args.server_pub {
        h.clone()
    } else {
        std::fs::read_to_string(&args.pub_file)?.trim().to_string()
    };
    let v = hex::decode(hex_s.trim())?;
    if v.len() != 32 {
        bail!("pub must be 32 bytes hex");
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

fn load_tls(path: &PathBuf) -> Result<LabTlsMaterial> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(LabTlsMaterial {
        cert_der: hex::decode(v["cert_hex"].as_str().context("cert_hex")?)?,
        key_der: hex::decode(v["key_hex"].as_str().context("key_hex")?)?,
        server_name: v["sni"].as_str().unwrap_or("cover.local").to_string(),
    })
}

async fn socks_handshake(sock: &mut TcpStream) -> Result<(String, u16)> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        bail!("not socks5");
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        bail!("only CONNECT");
    }
    let host = match req[3] {
        0x01 => {
            let mut ip = [0u8; 4];
            sock.read_exact(&mut ip).await?;
            format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
        }
        0x03 => {
            let mut ln = [0u8; 1];
            sock.read_exact(&mut ln).await?;
            let mut name = vec![0u8; ln[0] as usize];
            sock.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).to_string()
        }
        0x04 => bail!("ipv6 later"),
        _ => bail!("bad atype"),
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok((host, port))
}

async fn pump_session<S>(
    mut local: TcpStream,
    mut remote: S,
    server_pub: [u8; 32],
    target: String,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (hello, eph) = client_hello_inner(server_pub, 0x07);
    write_pref(&mut remote, &hello).await?;
    let server_raw = read_pref(&mut remote).await?;
    let keys = client_finish_keys(server_pub, &eph, &hello, &server_raw)?;
    let mut sess = SessionTransport::new_client(keys, Shaper::new(ShaperProfile::default()));
    let mut mux = Mux::new_client();
    // Optional MASK_OFFER from edge before STREAM_OPEN
    let sealed0 = read_pref(&mut remote).await?;
    let (frame0, _) = sess.open_frame(&sealed0)?;
    if frame0.ty == FrameType::Control {
        if let Some((swif_wire::CtrlType::MaskOffer, payload)) = swif_wire::parse_ctrl(&frame0) {
            if let Some((id, _hash)) = swif_wire::parse_mask_offer(&payload) {
                info!("MASK_OFFER {id}");
                let ack = swif_wire::mask_ack(&id, true);
                write_pref(&mut remote, &sess.seal_frame(&ack)?).await?;
            }
        }
    }

    let (sid, open) = mux.open_stream(target.into_bytes());
    write_pref(&mut remote, &sess.seal_frame(&open)?).await?;

    let mut local_buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            n = local.read(&mut local_buf) => {
                let n = n?;
                if n == 0 {
                    let fin = mux.data_frame(sid, b"")?;
                    write_pref(&mut remote, &sess.seal_frame(&fin)?).await?;
                    return Ok(());
                }
                let f = mux.data_frame(sid, &local_buf[..n])?;
                write_pref(&mut remote, &sess.seal_frame(&f)?).await?;
            }
            sealed = read_pref(&mut remote) => {
                let sealed = sealed?;
                let (frame, _) = sess.open_frame(&sealed)?;
                match frame.ty {
                    FrameType::StreamData => {
                        let (id, data) = mux.on_data(&frame)?;
                        if id != sid { continue; }
                        if data.is_empty() { return Ok(()); }
                        local.write_all(&data).await?;
                    }
                    FrameType::StreamReset => return Ok(()),
                    FrameType::Pong => {}
                    FrameType::Control => {}
                    _ => {}
                }
            }
        }
    }
}

async fn proxy_null(local: TcpStream, server: SocketAddr, server_pub: [u8; 32], target: String) -> Result<()> {
    let remote = NullTcp.dial(server).await?;
    pump_session(local, remote, server_pub, target).await
}

async fn proxy_tls(
    local: TcpStream,
    server: SocketAddr,
    server_pub: [u8; 32],
    target: String,
    material: &LabTlsMaterial,
) -> Result<()> {
    let remote = dial_tls(server, material).await?;
    pump_session(local, remote, server_pub, target).await
}

async fn proxy_quic(
    mut local: TcpStream,
    server: SocketAddr,
    server_pub: [u8; 32],
    target: String,
) -> Result<()> {
    let q = QuicFastClient::dial(server).await?;
    let (hello, eph) = client_hello_inner(server_pub, 0x07);
    q.send_pref(&hello).await?;
    let server_raw = q.recv_pref().await?;
    let keys = client_finish_keys(server_pub, &eph, &hello, &server_raw)?;
    let mut sess = SessionTransport::new_client(keys, Shaper::new(ShaperProfile::default()));
    let mut mux = Mux::new_client();
    let (sid, open) = mux.open_stream(target.into_bytes());
    q.send_pref(&sess.seal_frame(&open)?).await?;

    // Simplified: read all local → one datagram; wait response datagrams
    let mut local_buf = vec![0u8; 32 * 1024];
    let n = local.read(&mut local_buf).await?;
    let f = mux.data_frame(sid, &local_buf[..n])?;
    q.send_pref(&sess.seal_frame(&f)?).await?;
    if n > 0 {
        // signal fin
        let fin = mux.data_frame(sid, b"")?;
        q.send_pref(&sess.seal_frame(&fin)?).await?;
    }
    loop {
        let sealed = q.recv_pref().await?;
        let (frame, _) = sess.open_frame(&sealed)?;
        if let FrameType::StreamData = frame.ty {
            let (id, data) = mux.on_data(&frame)?;
            if id != sid {
                continue;
            }
            if !data.is_empty() {
                local.write_all(&data).await?;
            }
            if data.is_empty() || data.len() < 32 * 1024 {
                break;
            }
        } else {
            break;
        }
    }
    Ok(())
}

async fn open_session_null(
    server: SocketAddr,
    server_pub: [u8; 32],
) -> Result<(TcpStream, SessionTransport, Mux)> {
    let mut remote = NullTcp.dial(server).await?;
    let (hello, eph) = client_hello_inner(server_pub, 0x07);
    write_pref(&mut remote, &hello).await?;
    let server_raw = read_pref(&mut remote).await?;
    let keys = client_finish_keys(server_pub, &eph, &hello, &server_raw)?;
    let mut sess = SessionTransport::new_client(keys, Shaper::new(ShaperProfile::default()));
    let mux = Mux::new_client();
    let sealed0 = read_pref(&mut remote).await?;
    let (frame0, _) = sess.open_frame(&sealed0)?;
    if frame0.ty == FrameType::Control {
        if let Some((swif_wire::CtrlType::MaskOffer, payload)) = swif_wire::parse_ctrl(&frame0) {
            if let Some((id, _)) = swif_wire::parse_mask_offer(&payload) {
                let ack = swif_wire::mask_ack(&id, true);
                write_pref(&mut remote, &sess.seal_frame(&ack)?).await?;
            }
        }
    }
    Ok((remote, sess, mux))
}

async fn udp_ping_once(server: SocketAddr, server_pub: [u8; 32], target: SocketAddr) -> Result<()> {
    let SocketAddr::V4(v4) = target else {
        bail!("udp-ping IPv4 only");
    };
    let (mut remote, mut sess, _mux) = open_session_null(server, server_pub).await?;
    let payload = encode_udp4(v4.ip().octets(), v4.port(), b"swif-udp-ping");
    let frame = Mux::datagram_frame(1, &payload);
    write_pref(&mut remote, &sess.seal_frame(&frame)?).await?;
    // Also send HEALTH
    let health = swif_wire::health(1, 0);
    write_pref(&mut remote, &sess.seal_frame(&health)?).await?;
    // Read replies (health and/or datagram)
    for _ in 0..4 {
        let sealed = tokio::time::timeout(std::time::Duration::from_secs(5), read_pref(&mut remote))
            .await
            .context("udp ping timeout")??;
        let (frame, _) = sess.open_frame(&sealed)?;
        match frame.ty {
            FrameType::Datagram => {
                let (_id, body) = Mux::parse_datagram(&frame)?;
                if let Some((ip, port, data)) = decode_udp4(&body) {
                    info!(
                        "UDP reply from {}:{port} len={}",
                        std::net::Ipv4Addr::from(ip),
                        data.len()
                    );
                    println!("UDP_PING OK {} bytes", data.len());
                    return Ok(());
                }
            }
            FrameType::Control => {
                info!("control frame during udp-ping");
            }
            _ => {}
        }
    }
    bail!("no UDP reply");
}

async fn tun_smoke_once(server: SocketAddr, server_pub: [u8; 32]) -> Result<()> {
    let tun = NullTun::new(1500);
    // Minimal IPv4 header-ish (20 bytes): version/ihl=0x45
    let mut pkt = vec![0u8; 20];
    pkt[0] = 0x45;
    pkt[2] = 0;
    pkt[3] = 20;
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&[10, 8, 0, 2]);
    pkt[16..20].copy_from_slice(&[10, 8, 0, 1]);
    tun.inject_from_stack(&pkt).await?;

    let (mut remote, mut sess, _mux) = open_session_null(server, server_pub).await?;
    let mut buf = [0u8; 1500];
    let n = tun.read_packet(&mut buf).await?;
    let frame = swif_mux::Mux::datagram_frame(TUN_ASSOC, &buf[..n]);
    write_pref(&mut remote, &sess.seal_frame(&frame)?).await?;

    let sealed = tokio::time::timeout(std::time::Duration::from_secs(5), read_pref(&mut remote))
        .await
        .context("tun smoke timeout")??;
    let (frame, _) = sess.open_frame(&sealed)?;
    if frame.ty != FrameType::Datagram {
        bail!("expected datagram echo");
    }
    frame_to_tun(tun.as_ref(), &frame).await?;
    let out = tun.drain_to_stack().await;
    if out.is_empty() || out[0][0] != 0x45 {
        bail!("bad tun echo");
    }
    println!("TUN_SMOKE OK {} bytes", out[0].len());
    Ok(())
}

async fn try_os_tun_open() -> Result<()> {
    use std::net::Ipv4Addr;
    match swif_tun::OsTun::open("SwifTun", Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(255, 255, 255, 0), 1400)
    {
        Ok(_) => {
            println!("OS_TUN OPEN OK (adapter SwifTun)");
            Ok(())
        }
        Err(e) => {
            bail!("OS TUN open failed: {e} (admin + wintun.dll + --features os-tun?)");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    let args = Args::parse();
    let pubk = load_pub(&args).context("server pub")?;
    let _ = StaticKeypair::generate().public_bytes();

    if let Some(target) = args.udp_ping {
        info!("udp-ping {target} via {}", args.server);
        return udp_ping_once(args.server, pubk, target).await;
    }
    if args.tun {
        // Best-effort OS open; always run NullTun path through edge for E2E.
        match try_os_tun_open().await {
            Ok(()) => {}
            Err(e) => tracing::warn!("{e:#}"),
        }
        info!("tun-smoke via {}", args.server);
        return tun_smoke_once(args.server, pubk).await;
    }
    if args.tun_smoke {
        info!("tun-smoke via {}", args.server);
        return tun_smoke_once(args.server, pubk).await;
    }

    info!(
        "swif-cli socks {} → server {} mask={}",
        args.socks, args.server, args.mask
    );
    let tls = if args.mask == "tls13_stable" {
        Some(load_tls(&args.tls_material)?)
    } else {
        None
    };
    let listener = TcpListener::bind(args.socks).await?;
    loop {
        let (mut sock, _) = listener.accept().await?;
        let server = args.server;
        let mask = args.mask.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let run = async {
                let (host, port) = socks_handshake(&mut sock).await?;
                let target = format!("{host}:{port}");
                info!("CONNECT {target}");
                match mask.as_str() {
                    "null_tcp" => proxy_null(sock, server, pubk, target).await,
                    "tls13_stable" => {
                        proxy_tls(sock, server, pubk, target, tls.as_ref().unwrap()).await
                    }
                    "quic_fast" => proxy_quic(sock, server, pubk, target).await,
                    other => bail!("unknown mask {other}"),
                }
            };
            if let Err(e) = run.await {
                error!("{e:#}");
            }
        });
    }
}
