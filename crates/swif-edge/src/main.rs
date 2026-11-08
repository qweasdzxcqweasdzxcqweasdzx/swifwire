//! SwifWire edge: null_tcp | tls13_stable (+ cover mirror) | quic_fast UDP.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use swif_crypto::{StaticKeypair, TicketReplayWindow};
use swif_mask::{
    accept_tls, decode_pref_datagram, encode_pref_datagram_slice, plausible_hello_len, read_pref,
    read_pref_timeout, serve_cover, write_pem, write_pref, CoverMode, LabTlsMaterial,
    QuicStableHints, quic_stable_accept_bi, quic_stable_bind_server, quic_stable_lab_allowed,
};
use swif_mux::Mux;
use swif_session::{server_respond_keys_ex_replay, SessionTransport};
use tokio::sync::Mutex as AsyncMutex;
use swif_shape::{Shaper, ShaperProfile};
use swif_tun::{decode_udp4, encode_udp4_reply};
use swif_wire::{Frame, FrameType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "swif-edge")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:9443")]
    listen: SocketAddr,
    #[arg(long, default_value = "server.key")]
    key: PathBuf,
    #[arg(long, default_value = "server.pub")]
    pub_out: PathBuf,
    /// null_tcp | tls13_stable | quic_stable | quic_fast/quic_lab
    #[arg(long, default_value = "tls13_stable")]
    mask: String,
    /// Upstream cover origin `host:port` (plain TCP after TLS terminate). Prod: required unless SWIF_LAB=1.
    #[arg(long)]
    cover: Option<SocketAddr>,
    /// Alias for --cover (ops / SERVER_OPS naming).
    #[arg(long)]
    cover_upstream: Option<SocketAddr>,
    #[arg(long, default_value = "cover.local")]
    sni: String,
    #[arg(long, default_value = "lab-cert.der.json")]
    tls_material: PathBuf,
    /// PEM certificate (leaf or chain). Overrides JSON material when set with --tls-key.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// PEM private key (PKCS8).
    #[arg(long)]
    tls_key: Option<PathBuf>,
}

fn load_or_create_key(path: &PathBuf, pub_path: &PathBuf) -> Result<StaticKeypair> {
    use rand::RngCore;
    let kp = if path.exists() {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            bail!("key must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        StaticKeypair::from_secret_bytes(arr)
    } else {
        let mut sec = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sec);
        let kp = StaticKeypair::from_secret_bytes(sec);
        std::fs::write(path, sec)?;
        info!("generated {}", path.display());
        kp
    };
    std::fs::write(pub_path, hex::encode(kp.public_bytes()))?;
    Ok(kp)
}

fn lab_mode() -> bool {
    std::env::var("SWIF_LAB").ok().as_deref() == Some("1")
}

#[derive(Default)]
struct EdgeMetrics {
    handshake_ok: AtomicU64,
    cover_path: AtomicU64,
    rekey_ok: AtomicU64,
}

impl EdgeMetrics {
    fn snapshot(&self) -> String {
        format!(
            "handshake_ok={} cover_path={} rekey_ok={}",
            self.handshake_ok.load(Ordering::Relaxed),
            self.cover_path.load(Ordering::Relaxed),
            self.rekey_ok.load(Ordering::Relaxed),
        )
    }
}

fn resolve_cover(args: &Args) -> Option<SocketAddr> {
    args.cover_upstream.or(args.cover)
}

fn load_tls_material(args: &Args) -> Result<LabTlsMaterial> {
    if let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) {
        return Ok(LabTlsMaterial::from_pem_files(cert, key, &args.sni)?);
    }
    // Prod (no SWIF_LAB): PEM pair is mandatory — JSON lab material is not a cover-grade cert path.
    if !lab_mode() {
        bail!("tls13_stable prod requires --tls-cert and --tls-key PEM (set SWIF_LAB=1 for JSON/auto lab material)");
    }
    let path = &args.tls_material;
    if path.exists() {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
        Ok(LabTlsMaterial {
            cert_der: hex::decode(v["cert_hex"].as_str().context("cert_hex")?)?,
            key_der: hex::decode(v["key_hex"].as_str().context("key_hex")?)?,
            server_name: v["sni"].as_str().unwrap_or(&args.sni).to_string(),
            hints: Default::default(),
        })
    } else {
        let m = LabTlsMaterial::generate(&args.sni)?;
        let doc = serde_json::json!({
            "sni": m.server_name,
            "cert_hex": hex::encode(&m.cert_der),
            "key_hex": hex::encode(&m.key_der),
        });
        std::fs::write(path, serde_json::to_vec_pretty(&doc)?)?;
        let _ = write_pem(&m, &PathBuf::from("lab-cover.crt"), &PathBuf::from("lab-cover.key"));
        info!("generated TLS material {} (SWIF_LAB)", path.display());
        Ok(m)
    }
}

fn cover_mode_for(upstream: Option<SocketAddr>) -> Result<CoverMode> {
    if upstream.is_some() {
        return Ok(CoverMode::MirrorUpstream);
    }
    if lab_mode() {
        return Ok(CoverMode::BuiltinHttp);
    }
    bail!("tls13_stable prod requires --cover / --cover-upstream (or SWIF_LAB=1 for builtin cover)")
}

async fn session_loop<S>(
    mut client: S,
    key: Arc<StaticKeypair>,
    hello: Vec<u8>,
    replay: Arc<AsyncMutex<TicketReplayWindow>>,
    mask_id: &str,
    metrics: Option<Arc<EdgeMetrics>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let master = key.public_bytes();
    let (server_raw, keys, resumed) = {
        let mut w = replay.lock().await;
        server_respond_keys_ex_replay(&key, &master, &hello, 0x07, Some(&mut w))
            .context("handshake")?
    };
    if resumed {
        info!("ticket resume ok");
    }
    if let Some(m) = &metrics {
        m.handshake_ok.fetch_add(1, Ordering::Relaxed);
    }
    write_pref(&mut client, &server_raw).await?;
    post_handshake_loop(client, keys, mask_id, metrics).await
}

async fn handle_udp_datagram<S>(
    client: &mut S,
    sess: &mut SessionTransport,
    frame: &Frame,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let (assoc, payload) = Mux::parse_datagram(frame)?;
    // Lab TUN: raw IPv4/IPv6 L3 → echo (OS routing lands later with wintun).
    if matches!(payload.first(), Some(0x45 | 0x60)) {
        info!("TUN L3 echo {} bytes assoc={assoc}", payload.len());
        let out = Mux::datagram_frame(assoc, &payload);
        write_pref(client, &sess.seal_frame(&out)?).await?;
        return Ok(());
    }
    let Some((ip, port, data)) = decode_udp4(&payload) else {
        warn!("bad datagram payload");
        return Ok(());
    };
    let addr = SocketAddr::from((std::net::Ipv4Addr::from(ip), port));
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(data, addr).await?;
    let mut buf = vec![0u8; 64 * 1024];
    let (n, from) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .context("udp recv timeout")??;
    let src_ip = match from {
        SocketAddr::V4(v4) => v4.ip().octets(),
        _ => ip,
    };
    let reply_body = encode_udp4_reply(src_ip, from.port(), &buf[..n]);
    let out = Mux::datagram_frame(assoc, &reply_body);
    write_pref(client, &sess.seal_frame(&out)?).await?;
    Ok(())
}

fn parse_target_from_open_body(body: &[u8]) -> Result<String> {
    if body.len() < 9 {
        bail!("short open");
    }
    let (mlen, vn) = swif_wire::decode_varint_u32(&body[8..])?;
    let start = 8 + vn;
    let end = start + mlen as usize;
    if end > body.len() {
        bail!("meta truncated");
    }
    Ok(String::from_utf8_lossy(&body[start..end]).to_string())
}

async fn bidirectional_proxy<S>(
    client: &mut S,
    sess: &mut SessionTransport,
    mux: &mut Mux,
    sid: u32,
    remote: &mut TcpStream,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut remote_buf = vec![0u8; 32 * 1024];
    loop {
        tokio::select! {
            sealed = read_pref(client) => {
                let sealed = sealed?;
                let (frame, _) = sess.open_frame(&sealed)?;
                match frame.ty {
                    FrameType::StreamData => {
                        let (id, data) = mux.on_data(&frame)?;
                        if id != sid { continue; }
                        if data.is_empty() {
                            return Ok(());
                        }
                        remote.write_all(&data).await?;
                    }
                    FrameType::StreamReset => return Ok(()),
                    FrameType::Ping => {
                        let pong = Frame::new(FrameType::Pong, frame.body.clone());
                        write_pref(client, &sess.seal_frame(&pong)?).await?;
                    }
                    _ => {}
                }
            }
            n = remote.read(&mut remote_buf) => {
                let n = n?;
                if n == 0 {
                    let fin = mux.data_frame(sid, b"")?;
                    write_pref(client, &sess.seal_frame(&fin)?).await?;
                    return Ok(());
                }
                let f = mux.data_frame(sid, &remote_buf[..n])?;
                write_pref(client, &sess.seal_frame(&f)?).await?;
            }
        }
    }
}

async fn handle_null(
    mut client: TcpStream,
    key: Arc<StaticKeypair>,
    replay: Arc<AsyncMutex<TicketReplayWindow>>,
) -> Result<()> {
    let hello = read_pref(&mut client).await.context("client hello")?;
    session_loop(client, key, hello, replay, "null_tcp", None).await
}

async fn handle_tls(
    tcp: TcpStream,
    key: Arc<StaticKeypair>,
    acceptor: Arc<tokio_rustls::TlsAcceptor>,
    cover: Option<SocketAddr>,
    cover_mode: CoverMode,
    replay: Arc<AsyncMutex<TicketReplayWindow>>,
    metrics: Arc<EdgeMetrics>,
) -> Result<()> {
    let mut tls = accept_tls(tcp, &acceptor).await?;
    let mut lb = [0u8; 4];
    if tls.read_exact(&mut lb).await.is_err() {
        return Ok(());
    }
    let n = u32::from_be_bytes(lb) as usize;
    if !plausible_hello_len(n) {
        let mut prefix = lb.to_vec();
        let mut extra = vec![0u8; 2048];
        if let Ok(m) = tokio::time::timeout(
            std::time::Duration::from_millis(80),
            tls.read(&mut extra),
        )
        .await
        {
            if let Ok(m) = m {
                prefix.extend_from_slice(&extra[..m]);
            }
        }
        info!("probe/cover path (bad len={n}) mode={cover_mode:?}");
        metrics.cover_path.fetch_add(1, Ordering::Relaxed);
        serve_cover(tls, &prefix, cover_mode, cover).await?;
        return Ok(());
    }
    let mut hello = vec![0u8; n];
    tls.read_exact(&mut hello).await?;
    let master = key.public_bytes();
    let hs = {
        let mut w = replay.lock().await;
        server_respond_keys_ex_replay(&key, &master, &hello, 0x07, Some(&mut w))
    };
    match hs {
        Ok((server_raw, keys, resumed)) => {
            if resumed {
                info!("tls ticket resume ok");
            }
            metrics.handshake_ok.fetch_add(1, Ordering::Relaxed);
            write_pref(&mut tls, &server_raw).await?;
            post_handshake_loop(tls, keys, "tls13_stable", Some(metrics)).await
        }
        Err(e) => {
            info!("inner auth fail → cover ({e}) mode={cover_mode:?}");
            metrics.cover_path.fetch_add(1, Ordering::Relaxed);
            let mut prefix = Vec::with_capacity(4 + hello.len());
            prefix.extend_from_slice(&lb);
            prefix.extend_from_slice(&hello);
            serve_cover(tls, &prefix, cover_mode, cover).await?;
            Ok(())
        }
    }
}

async fn post_handshake_loop<S>(
    mut client: S,
    keys: swif_crypto::SessionKeys,
    mask_id: &str,
    metrics: Option<Arc<EdgeMetrics>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut sess = SessionTransport::new_server(keys, Shaper::new(ShaperProfile::desktop()));
    let mut mux = Mux::new_server();
    let offer = swif_wire::mask_offer(mask_id, "lab");
    write_pref(&mut client, &sess.seal_frame(&offer)?).await?;
    loop {
        let sealed = match read_pref_timeout(&mut client, sess.idle_timeout()).await? {
            Some(s) => s,
            None => {
                if let Some(idle) = sess.seal_idle_cover()? {
                    write_pref(&mut client, &idle).await?;
                }
                continue;
            }
        };
        let (frame, _) = sess.open_frame(&sealed)?;
        match frame.ty {
            FrameType::Control => {
                if let Some((ty, p)) = swif_wire::parse_ctrl(&frame) {
                    match ty {
                        swif_wire::CtrlType::MaskAck => {
                            if let Some((id, ok)) = swif_wire::parse_mask_ack(&p) {
                                info!("MASK_ACK {id} applied={ok}");
                            }
                        }
                        swif_wire::CtrlType::Health => {
                            if let Some((rtt, loss)) = swif_wire::parse_health(&p) {
                                let reply = swif_wire::health(rtt, loss);
                                write_pref(&mut client, &sess.seal_frame(&reply)?).await?;
                            }
                        }
                        swif_wire::CtrlType::Rekey => {
                            if let Some(epoch) = swif_wire::parse_rekey(&p) {
                                if epoch == sess.epoch() + 1 {
                                    // Ack under current keys, then flip epoch together.
                                    write_pref(
                                        &mut client,
                                        &sess.seal_frame(&swif_wire::rekey(epoch))?,
                                    )
                                    .await?;
                                    sess.advance_rekey(epoch)?;
                                    if let Some(m) = &metrics {
                                        m.rekey_ok.fetch_add(1, Ordering::Relaxed);
                                    }
                                    info!("rekey applied epoch={epoch}");
                                }
                            }
                        }
                        swif_wire::CtrlType::Early => {
                            if let Some((reason, note)) = swif_wire::parse_early_ctrl(&p) {
                                info!("EARLY reason={reason} note={note}");
                            }
                        }
                        _ => {}
                    }
                }
            }
            FrameType::StreamOpen => {
                let sid = mux.accept_open(&frame)?;
                let target = parse_target_from_open_body(&frame.body)?;
                info!("stream {sid} → {target}");
                let mut remote = TcpStream::connect(&target).await?;
                bidirectional_proxy(&mut client, &mut sess, &mut mux, sid, &mut remote).await?;
                return Ok(());
            }
            FrameType::Datagram => {
                handle_udp_datagram(&mut client, &mut sess, &frame).await?;
            }
            FrameType::Ping => {
                let pong = Frame::new(FrameType::Pong, frame.body.clone());
                write_pref(&mut client, &sess.seal_frame(&pong)?).await?;
            }
            other => warn!("unexpected frame {other:?}"),
        }
    }
}

async fn run_quic_stable(
    args: Args,
    key: Arc<StaticKeypair>,
    replay: Arc<AsyncMutex<TicketReplayWindow>>,
) -> Result<()> {
    if !quic_stable_lab_allowed() {
        bail!("quic_stable is lab-gated; set SWIF_ALLOW_QUIC_STABLE=1 or SWIF_LAB=1");
    }
    let material = load_tls_material(&args)?;
    let hints = QuicStableHints::default();
    let endpoint = quic_stable_bind_server(args.listen, &material, &hints)?;
    info!(
        "quic_stable QUIC listen {} alpn={:?}",
        endpoint.local_addr()?,
        hints.alpn
    );
    loop {
        let accepted = quic_stable_accept_bi(&endpoint).await?;
        let key = key.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            // Keep Connection alive for the stream lifetime.
            let _conn = accepted.conn;
            let mut stream = accepted.stream;
            if let Err(e) = async {
                let hello = read_pref(&mut stream).await.context("quic hello")?;
                session_loop(stream, key, hello, replay, "quic_stable", None).await
            }
            .await
            {
                error!("quic_stable session: {e:#}");
            }
        });
    }
}

async fn run_quic(
    listen: SocketAddr,
    key: Arc<StaticKeypair>,
    replay: Arc<AsyncMutex<TicketReplayWindow>>,
) -> Result<()> {
    let sock = Arc::new(UdpSocket::bind(listen).await?);
    info!("quic_fast UDP listen {listen}");
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let (n, peer) = sock.recv_from(&mut buf).await?;
        let Some((dcid, hello)) = decode_pref_datagram(&buf[..n]) else {
            continue;
        };
        let sock = sock.clone();
        let key = key.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_quic_session(sock, peer, dcid, hello, key, replay).await {
                error!("quic {peer}: {e:#}");
            }
        });
    }
}

async fn handle_quic_session(
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    dcid: Vec<u8>,
    hello: Vec<u8>,
    key: Arc<StaticKeypair>,
    replay: Arc<AsyncMutex<TicketReplayWindow>>,
) -> Result<()> {
    let master = key.public_bytes();
    let (server_raw, keys, _) = {
        let mut w = replay.lock().await;
        server_respond_keys_ex_replay(&key, &master, &hello, 0x07, Some(&mut w))?
    };
    let pkt = encode_pref_datagram_slice(&dcid, &server_raw);
    sock.send_to(&pkt, peer).await?;

    let mut sess = SessionTransport::new_server(keys, Shaper::new(ShaperProfile::desktop()));
    let mut mux = Mux::new_server();
    let mut buf = vec![0u8; 64 * 1024];

    // Expect STREAM_OPEN then DATA — simplified single-stream over UDP datagrams
    let n = sock.recv_from(&mut buf).await?;
    let (_id, sealed) = decode_pref_datagram(&buf[..n.0])
        .ok_or_else(|| anyhow::anyhow!("bad datagram"))?;
    let (frame, _) = sess.open_frame(&sealed)?;
    if frame.ty != FrameType::StreamOpen {
        bail!("expected open");
    }
    let sid = mux.accept_open(&frame)?;
    let target = parse_target_from_open_body(&frame.body)?;
    info!("quic stream {sid} → {target}");
    let mut remote = TcpStream::connect(&target).await?;

    // one-shot: collect client data datagrams until empty, write remote, reply
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let (n, from) = r?;
                if from != peer { continue; }
                let Some((_, sealed)) = decode_pref_datagram(&buf[..n]) else { continue; };
                let (frame, _) = sess.open_frame(&sealed)?;
                match frame.ty {
                    FrameType::StreamData => {
                        let (id, data) = mux.on_data(&frame)?;
                        if id != sid { continue; }
                        if data.is_empty() {
                            return Ok(());
                        }
                        remote.write_all(&data).await?;
                        // read remote response chunk
                        let mut rb = vec![0u8; 32 * 1024];
                        let rn = remote.read(&mut rb).await?;
                        let f = mux.data_frame(sid, &rb[..rn])?;
                        let out = encode_pref_datagram_slice(&dcid, &sess.seal_frame(&f)?);
                        sock.send_to(&out, peer).await?;
                        if rn == 0 {
                            return Ok(());
                        }
                    }
                    FrameType::StreamReset => return Ok(()),
                    _ => {}
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();
    let args = Args::parse();
    let key = Arc::new(load_or_create_key(&args.key, &args.pub_out)?);
    let replay = Arc::new(AsyncMutex::new(TicketReplayWindow::new(4096)));
    info!(
        "swif-edge listen {} mask={} pub={}",
        args.listen,
        args.mask,
        hex::encode(key.public_bytes())
    );

    if args.mask == "quic_stable" {
        return run_quic_stable(args, key, replay).await;
    }
    if args.mask == "quic_fast" || args.mask == "quic_lab" {
        if !lab_mode() {
            warn!("quic_fast/quic_lab is thin UDP cover — lab only; set SWIF_LAB=1 to silence");
        }
        return run_quic(args.listen, key, replay).await;
    }
    if args.mask == "tls13_stable" {
        if !lab_mode() {
            if args.tls_cert.is_none() || args.tls_key.is_none() {
                bail!(
                    "prod tls13_stable requires --tls-cert and --tls-key PEM (or SWIF_LAB=1 for JSON/lab material)"
                );
            }
            if resolve_cover(&args).is_none() {
                bail!("prod tls13_stable requires --cover / --cover-upstream");
            }
        }
        let cover = resolve_cover(&args);
        let cover_mode = cover_mode_for(cover)?;
        let material = load_tls_material(&args)?;
        let acceptor = Arc::new(material.acceptor()?);
        let metrics = Arc::new(EdgeMetrics::default());
        info!("tls cover_mode={cover_mode:?} upstream={cover:?}");
        let listener = TcpListener::bind(args.listen).await?;
        let metrics_log = metrics.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                info!("metrics {}", metrics_log.snapshot());
            }
        });
        loop {
            let (sock, peer) = listener.accept().await?;
            let key = key.clone();
            let acceptor = acceptor.clone();
            let replay = replay.clone();
            let metrics = metrics.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    handle_tls(sock, key, acceptor, cover, cover_mode, replay, metrics).await
                {
                    error!("tls peer {peer}: {e:#}");
                }
            });
        }
    }
    if args.mask != "null_tcp" {
        bail!("unknown mask {}", args.mask);
    }
    if std::env::var("SWIF_ALLOW_NULL").ok().as_deref() != Some("1") {
        bail!("null_tcp is lab-only; set SWIF_ALLOW_NULL=1 or use --mask tls13_stable");
    }
    let listener = TcpListener::bind(args.listen).await?;
    loop {
        let (sock, peer) = listener.accept().await?;
        let key = key.clone();
        let replay = replay.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_null(sock, key, replay).await {
                error!("peer {peer}: {e:#}");
            }
        });
    }
}
