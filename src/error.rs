//! Typed errors. Parser failure never panics; it returns recovery outcomes.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// I/O failure while reading a source.
    Io(std::io::Error),
    /// A byte range was out of bounds for the underlying source.
    OutOfBounds {
        offset: u64,
        len: u64,
        source_len: u64,
    },
    /// Format-specific structural validation failed.
    Validation {
        format: &'static str,
        reason: String,
    },
    /// A configured engine limit was hit.
    LimitExceeded { limit: &'static str, detail: String },
    /// Decompression/expansion failed (corrupt stream, ratio bomb, ...).
    Decompression(String),
    /// Extraction was refused by the safety layer.
    UnsafePath { path: String, reason: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::OutOfBounds {
                offset,
                len,
                source_len,
            } => write!(
                f,
                "read out of bounds: offset={offset} len={len} source_len={source_len}"
            ),
            Error::Validation { format, reason } => write!(f, "{format}: {reason}"),
            Error::LimitExceeded { limit, detail } => {
                write!(f, "limit exceeded ({limit}): {detail}")
            }
            Error::Decompression(msg) => write!(f, "decompression failed: {msg}"),
            Error::UnsafePath { path, reason } => write!(f, "unsafe path {path:?}: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
