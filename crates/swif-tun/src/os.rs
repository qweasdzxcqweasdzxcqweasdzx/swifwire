//! Optional OS TUN (feature `os-tun`). Windows needs wintun.dll beside the binary.

#[cfg(feature = "os-tun")]
mod imp {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::Mutex;

    use crate::{Error, Result, TunDevice};

    /// Thin wrapper over `tun` crate AsyncDevice.
    pub struct OsTun {
        dev: Mutex<tun::AsyncDevice>,
        mtu: usize,
    }

    impl OsTun {
        /// Create TUN named `SwifTun` with given address (admin/root usually required).
        pub fn open(name: &str, address: Ipv4Addr, netmask: Ipv4Addr, mtu: u16) -> Result<Arc<Self>> {
            let mut cfg = tun::Configuration::default();
            cfg.tun_name(name)
                .address(address)
                .netmask(netmask)
                .mtu(mtu)
                .up();
            #[cfg(target_os = "windows")]
            cfg.platform_config(|p| {
                p.device_guid(1234567);
            });
            let dev = tun::create_as_async(&cfg).map_err(|e| Error::Io(e.to_string()))?;
            Ok(Arc::new(Self {
                dev: Mutex::new(dev),
                mtu: mtu as usize,
            }))
        }
    }

    #[async_trait]
    impl TunDevice for OsTun {
        async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
            use tokio::io::AsyncReadExt;
            let mut g = self.dev.lock().await;
            g.read(buf).await.map_err(|e| Error::Io(e.to_string()))
        }

        async fn write_packet(&self, packet: &[u8]) -> Result<()> {
            use tokio::io::AsyncWriteExt;
            let mut g = self.dev.lock().await;
            g.write_all(packet)
                .await
                .map_err(|e| Error::Io(e.to_string()))
        }

        fn mtu(&self) -> usize {
            self.mtu
        }
    }
}

#[cfg(feature = "os-tun")]
pub use imp::OsTun;

#[cfg(not(feature = "os-tun"))]
pub struct OsTun;

#[cfg(not(feature = "os-tun"))]
impl OsTun {
    pub fn open(
        _name: &str,
        _address: std::net::Ipv4Addr,
        _netmask: std::net::Ipv4Addr,
        _mtu: u16,
    ) -> crate::Result<std::sync::Arc<Self>> {
        Err(crate::Error::Io(
            "rebuild with --features os-tun (and wintun.dll on Windows)".into(),
        ))
    }
}
