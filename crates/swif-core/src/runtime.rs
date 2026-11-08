//! Live client runtime: local SOCKS5 → SwifWire edge (null_tcp / tls13_stable).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use swif_mask::{
    dial_tls_verify, parse_tls_verify, read_pref, write_pref, LabTlsMaterial, MaskDial, NullTcp,
    TlsPackHints, TlsVerifyMode,
};
use swif_mux::Mux;
use swif_session::{client_finish_keys, client_hello_inner, SessionTransport};
use swif_shape::{Shaper, ShaperProfile};
use swif_wire::FrameType;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::Outbound;
use crate::policy::DialPolicy;
use crate::CoreError;

pub struct RuntimeEngine {
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl RuntimeEngine {
    #[allow(dead_code)]
    pub fn spawn(outbound: Outbound) -> Result<Self, CoreError> {
        Self::spawn_with_hints(outbound, TlsPackHints::default())
    }

    pub fn spawn_with_hints(outbound: Outbound, hints: TlsPackHints) -> Result<Self, CoreError> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let join = thread::Builder::new()
            .name("swif-runtime".into())
            .spawn(move || {
                let rt = match Runtime::new() {
                    Ok(r) => r,
                    Err(e) => {
                        error!("runtime: {e}");
                        return;
                    }
                };
                if let Err(e) = rt.block_on(run_socks_loop(outbound, hints, stop2)) {
                    error!("swif runtime exited: {e:#}");
                }
            })
            .map_err(|e| CoreError::Msg(e.to_string()))?;
        // wait briefly for bind
        thread::sleep(Duration::from_millis(80));
        Ok(Self {
            stop,
            join: Some(join),
        })
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for RuntimeEngine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn parse_pub(hex_s: &str) -> Result<[u8; 32], CoreError> {
    let v = hex::decode(hex_s.trim()).map_err(|e| CoreError::Msg(e.to_string()))?;
    if v.len() != 32 {
        return Err(CoreError::Msg("pub must be 32 bytes".into()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

fn load_tls_material(path: &str) -> Result<LabTlsMaterial, CoreError> {
    let v: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path).map_err(|e| CoreError::Msg(e.to_string()))?,
    )
    .map_err(|e| CoreError::Msg(e.to_string()))?;
    Ok(LabTlsMaterial {
        cert_der: hex::decode(v["cert_hex"].as_str().unwrap_or(""))
            .map_err(|e| CoreError::Msg(e.to_string()))?,
        key_der: hex::decode(v["key_hex"].as_str().unwrap_or(""))
            .map_err(|e| CoreError::Msg(e.to_string()))?,
        server_name: v["sni"]
            .as_str()
            .unwrap_or("cover.local")
            .to_string(),
        hints: Default::default(),
    })
}

async fn run_socks_loop(
    outbound: Outbound,
    hints: TlsPackHints,
    stop: Arc<AtomicBool>,
) -> Result<(), CoreError> {
    let socks: SocketAddr = outbound
        .settings
        .socks_listen
        .parse()
        .map_err(|e: std::net::AddrParseError| CoreError::Msg(e.to_string()))?;
    let server: SocketAddr = format!(
        "{}:{}",
        outbound.settings.address, outbound.settings.port
    )
    .parse()
    .map_err(|e: std::net::AddrParseError| CoreError::Msg(e.to_string()))?;
    let pubk = parse_pub(&outbound.settings.server_pub_hex)?;
    let mut mask = outbound.settings.mask.clone();
    let verify = parse_tls_verify(&outbound.settings.tls_verify).unwrap_or(TlsVerifyMode::Pin);
    let tls = if mask == "tls13_stable" {
        let path = outbound
            .settings
            .tls_material_path
            .clone()
            .unwrap_or_else(|| "lab-cert.der.json".into());
        Some(load_tls_material(&path)?.with_hints(hints))
    } else {
        None
    };
    if mask == "quic_fast" || mask == "quic_lab" {
        return Err(CoreError::Msg(
            "quic_lab SOCKS runtime not in core yet; use swif-cli / SWIF_ALLOW_QUIC_LAB".into(),
        ));
    }
    // Commercial: null_tcp only with explicit lab opt-in.
    if mask == "null_tcp" && std::env::var("SWIF_ALLOW_NULL").ok().as_deref() != Some("1") {
        return Err(CoreError::Msg(
            "null_tcp is lab-only; set SWIF_ALLOW_NULL=1 or use tls13_stable".into(),
        ));
    }

    let policy = Arc::new(Mutex::new(DialPolicy::default()));
    {
        let mut p = policy.lock().await;
        if let Some(m) = crate::policy::MaskId::parse(&mask) {
            p.preferred = m;
        }
        p.set_legacy_fallback(outbound.settings.legacy_fallback_uri.clone());
    }

    let listener = TcpListener::bind(socks)
        .await
        .map_err(|e| CoreError::Msg(format!("socks bind {socks}: {e}")))?;
    info!(
        "swif-core runtime SOCKS {} → {} mask={} tls_verify={:?}",
        socks, server, mask, verify
    );

    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let accept = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
        let Ok(Ok((sock, _))) = accept else {
            continue;
        };
        {
            let p = policy.lock().await;
            mask = p.current().as_str().to_string();
        }
        let mask = mask.clone();
        let tls = tls.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_one(sock, server, pubk, &mask, tls.as_ref(), verify, policy).await
            {
                warn!("proxy: {e:#}");
            }
        });
    }
    Ok(())
}

async fn dial_null_retry(server: SocketAddr) -> anyhow::Result<TcpStream> {
    let mut last = None;
    for attempt in 1..=3u32 {
        match NullTcp.dial(server).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                warn!("edge dial attempt {attempt}/3 failed: {e}");
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(150 * attempt as u64)).await;
            }
        }
    }
    Err(last.unwrap().into())
}

async fn handle_one(
    mut local: TcpStream,
    server: SocketAddr,
    pubk: [u8; 32],
    mask: &str,
    tls: Option<&LabTlsMaterial>,
    verify: TlsVerifyMode,
    policy: Arc<Mutex<DialPolicy>>,
) -> anyhow::Result<()> {
    let (host, port) = socks_handshake(&mut local).await?;
    let target = format!("{host}:{port}");
    match mask {
        "null_tcp" => {
            let remote = dial_null_retry(server).await?;
            {
                let mut p = policy.lock().await;
                p.on_success();
            }
            pump_session(local, remote, pubk, target).await
        }
        "tls13_stable" => {
            let material = tls.ok_or_else(|| anyhow::anyhow!("tls material missing"))?;
            let mut last = None;
            for attempt in 1..=3u32 {
                match dial_tls_verify(server, material, verify).await {
                    Ok(remote) => {
                        {
                            let mut p = policy.lock().await;
                            p.on_success();
                        }
                        return pump_session(local, remote, pubk, target).await;
                    }
                    Err(e) => {
                        warn!("tls dial attempt {attempt}/3 failed: {e}");
                        let (backoff, legacy) = {
                            let mut p = policy.lock().await;
                            let (_next, ms) = p.on_handshake_timeout();
                            (ms, p.legacy_fallback_uri.clone())
                        };
                        last = Some(e);
                        if attempt == 3 {
                            if let Some(uri) = legacy {
                                warn!("swif dials exhausted; host app may use legacy_fallback_uri");
                                anyhow::bail!(
                                    "swif tls dial failed after retries; legacy_fallback_hint={uri}"
                                );
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(backoff.max(150) as u64)).await;
                    }
                }
            }
            Err(last.unwrap().into())
        }
        other => anyhow::bail!("unsupported mask {other}"),
    }
}

async fn socks_handshake(sock: &mut TcpStream) -> anyhow::Result<(String, u16)> {
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        anyhow::bail!("not socks5");
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods).await?;
    sock.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        anyhow::bail!("only CONNECT");
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
        _ => anyhow::bail!("bad atype"),
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
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (hello, eph) = client_hello_inner(server_pub, 0x07);
    write_pref(&mut remote, &hello).await?;
    let server_raw = read_pref(&mut remote).await?;
    let keys = client_finish_keys(server_pub, &eph, &hello, &server_raw)?;
    let mut sess = SessionTransport::new_client(keys, Shaper::new(ShaperProfile::desktop()));
    let mut mux = Mux::new_client();

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

    // Optional early rekey (epoch 1) — ack under old keys, then both advance.
    {
        let epoch = 1u64;
        let rk = swif_wire::rekey(epoch);
        write_pref(&mut remote, &sess.seal_frame(&rk)?).await?;
        let ack = read_pref(&mut remote).await?;
        let (af, _) = sess.open_frame(&ack)?;
        if let Some((swif_wire::CtrlType::Rekey, p)) = swif_wire::parse_ctrl(&af) {
            if swif_wire::parse_rekey(&p) == Some(epoch) {
                sess.advance_rekey(epoch)?;
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
                    FrameType::Control => {
                        if let Some((swif_wire::CtrlType::Rekey, p)) = swif_wire::parse_ctrl(&frame) {
                            if let Some(epoch) = swif_wire::parse_rekey(&p) {
                                if epoch == sess.epoch() + 1 {
                                    write_pref(
                                        &mut remote,
                                        &sess.seal_frame(&swif_wire::rekey(epoch))?,
                                    )
                                    .await?;
                                    sess.advance_rekey(epoch)?;
                                }
                            }
                        }
                    }
                    FrameType::Ping => {
                        let pong = swif_wire::Frame::new(FrameType::Pong, frame.body.clone());
                        write_pref(&mut remote, &sess.seal_frame(&pong)?).await?;
                    }
                    _ => {}
                }
            }
        }
    }
}

#[allow(dead_code)]
fn _path_touch() -> PathBuf {
    PathBuf::new()
}
