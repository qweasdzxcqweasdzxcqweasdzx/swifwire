//! Cover mirror / fake origin for failed inner auth (anti-probe).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const COVER_HTML: &[u8] = b"\
HTTP/1.1 200 OK\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Connection: close\r\n\
Content-Length: 73\r\n\
\r\n\
<!doctype html><html><body><h1>OK</h1><p>cover origin</p></body></html>";

/// Cover behavior after TLS (or null) accept, before/without inner auth success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverMode {
    /// Lab-only: fixed HTML 200.
    BuiltinHttp,
    /// Prod default when upstream configured: byte reverse-proxy to origin.
    MirrorUpstream,
}

/// Built-in HTTP cover response (no upstream). Lab / SWIF_LAB only.
pub async fn serve_builtin_http<S>(mut stream: S, prefix: &[u8]) -> std::io::Result<()>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let _ = prefix;
    let mut tmp = [0u8; 2048];
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        stream.read(&mut tmp),
    )
    .await;
    stream.write_all(COVER_HTML).await?;
    stream.flush().await?;
    Ok(())
}

/// Reverse-proxy remaining bytes + live stream to upstream cover origin (plain TCP).
pub async fn mirror_to_upstream<S>(
    client: S,
    prefix: &[u8],
    upstream: std::net::SocketAddr,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut up = TcpStream::connect(upstream).await?;
    if !prefix.is_empty() {
        up.write_all(prefix).await?;
    }
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = up.split();
    let c2u = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            uw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    let u2c = async {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = ur.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            cw.write_all(&buf[..n]).await?;
        }
        Ok::<(), std::io::Error>(())
    };
    tokio::select! {
        r = c2u => r?,
        r = u2c => r?,
    }
    Ok(())
}

/// Dispatch cover path by mode.
pub async fn serve_cover<S>(
    stream: S,
    prefix: &[u8],
    mode: CoverMode,
    upstream: Option<std::net::SocketAddr>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match mode {
        CoverMode::MirrorUpstream => {
            let up = upstream.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "mirror_upstream requires cover addr",
                )
            })?;
            mirror_to_upstream(stream, prefix, up).await
        }
        CoverMode::BuiltinHttp => serve_builtin_http(stream, prefix).await,
    }
}

/// Tiny local cover HTTP listener for lab (optional companion to edge).
pub async fn run_lab_cover(listen: std::net::SocketAddr) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    loop {
        let (mut sock, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(COVER_HTML).await;
        });
    }
}
