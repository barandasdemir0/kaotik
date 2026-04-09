//! Hata türleri ve `Result` tipi.
use std::fmt;

/// Kütüphane hata türü: parola, IO, şifreleme veya format.
#[derive(Debug)]
pub enum Error {
    Password(String),
    Io(std::io::Error),
    Crypto(String),
    Format(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Password(msg) => write!(f, "Password error: {}", msg),
            Error::Io(e) => write!(f, "IO error: {}", e),
            Error::Crypto(msg) => write!(f, "Crypto error: {}", msg),
            Error::Format(msg) => write!(f, "Format error: {}", msg),
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
