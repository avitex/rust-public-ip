use std::error::Error as StdError;
use std::fmt::Debug;
use std::net::AddrParseError;
use std::str::Utf8Error;

use thiserror::Error;

use crate::{dns, http};

/// An error produced while attempting to resolve
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("no or invalid IP address string found")]
    Addr,
    #[error("dns resolver: {0}")]
    Dns(dns::Error),
    #[error("http resolver: {0}")]
    Http(http::Error),
    #[error("other resolver: {0}")]
    Other(Box<dyn StdError + Send + Sync + 'static>),
}

impl Error {
    pub fn new<E>(error: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Other(Box::new(error))
    }
}

impl From<dns::Error> for Error {
    fn from(error: dns::Error) -> Self {
        Self::Dns(error)
    }
}

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
