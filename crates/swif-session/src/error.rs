use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Crypto(#[from] swif_crypto::Error),
    #[error(transparent)]
    Wire(#[from] swif_wire::Error),
    #[error("handshake failed")]
    Handshake,
    #[error("bad magic")]
    BadMagic,
    #[error("version mismatch")]
    Version,
}
