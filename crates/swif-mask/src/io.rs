//! Length-prefixed pipe IO used inside every mask underlay.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read_pref<R: AsyncRead + Unpin>(sock: &mut R) -> std::io::Result<Vec<u8>> {
    let mut lb = [0u8; 4];
    sock.read_exact(&mut lb).await?;
    let n = u32::from_be_bytes(lb) as usize;
    if n > 16 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n];
    sock.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_pref<W: AsyncWrite + Unpin>(sock: &mut W, data: &[u8]) -> std::io::Result<()> {
    sock.write_all(&(data.len() as u32).to_be_bytes()).await?;
    sock.write_all(data).await?;
    sock.flush().await?;
    Ok(())
}

/// Looks like a plausible ClientHelloInner size (magic+fields).
pub fn plausible_hello_len(n: usize) -> bool {
    (80..=64 * 1024).contains(&n)
}
