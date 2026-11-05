use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("buffer too short")]
    BufferTooShort,
    #[error("varint overflow")]
    VarintOverflow,
    #[error("unknown frame type {0:#x}")]
    UnknownFrameType(u8),
    #[error("invalid frame length")]
    InvalidLength,
    #[error("trailing bytes after frame")]
    TrailingBytes,
}
