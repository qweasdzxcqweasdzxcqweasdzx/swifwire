use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("aead decrypt failed")]
    Aead,
    #[error("wire: {0}")]
    Wire(#[from] swif_wire::Error),
    #[error("buffer too short")]
    BufferTooShort,
    #[error("counter overflow — rekey required")]
    CounterOverflow,
    #[error("ticket invalid or expired")]
    Ticket,
    #[error("ed25519 signature invalid")]
    Signature,
    #[error("bad key length")]
    BadKey,
}
