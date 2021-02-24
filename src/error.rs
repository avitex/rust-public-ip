use std::error::Error as StdError;
use std::fmt::Debug;
use std::net::AddrParseError;
use std::str::Utf8Error;

use thiserror::Error;

#[cfg(feature = "dns-resolver")]
use crate::dns;
#[cfg(feature = "http-resolver")]
use crate::http;

/// An error produced while attempting to resolve.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// No or invalid IP address string found.
    #[error("no or invalid IP address string found")]
    Addr,
    /// IP version not requested was returned.
    #[error("IP version not requested was returned")]
    Version,
    /// DNS resolver error.
    #[cfg(feature = "dns-resolver")]
    #[cfg_attr(docsrs, doc(cfg(feature = "dns-resolver")))]
    #[error("dns resolver: {0}")]
    Dns(dns::Error),
    /// HTTP resolver error.
    #[cfg(feature = "http-resolver")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http-resolver")))]
    #[error("http resolver: {0}")]
    Http(http::Error),
    /// Other resolver error.
    #[error("other resolver: {0}")]
    Other(Box<dyn StdError + Send + Sync + 'static>),
}

impl Error {
    /// Construct a new error.
    pub fn new<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Other(Box::new(error))
    }
}

#[cfg(feature = "dns-resolver")]
impl From<dns::Error> for Error {
    fn from(error: dns::Error) -> Self {
        Self::Dns(error)
    }
}

#[cfg(feature = "http-resolver")]
impl From<http::Error> for Error {
    fn from(error: http::Error) -> Self {
        Self::Http(error)
    }
}

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Self {
        Self::Addr
    }
}

impl From<AddrParseError> for Error {
    fn from(_: AddrParseError) -> Self {
        Self::Addr
    }
}
