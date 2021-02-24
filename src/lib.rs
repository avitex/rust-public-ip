mod error;

#[cfg(any(
    all(feature = "dns-resolver", not(feature = "tokio-dns-resolver")),
    all(feature = "http-resolver", not(feature = "tokio-http-resolver"))
))]
compile_error!("tokio is the only supported runtime currently - consider creating a PR or issue");

#[cfg(feature = "dns-resolver")]
pub mod dns;
#[cfg(feature = "http-resolver")]
pub mod http;

use std::any::Any;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::slice;
use std::task::{Context, Poll};

use futures_core::Stream;
use futures_util::stream::{self, BoxStream, StreamExt, TryStreamExt};
use futures_util::{future, ready};
use pin_project_lite::pin_project;

pub use crate::error::Error;

pub type Details = Box<dyn Any + Send + Sync + 'static>;
pub type Resolutions<'a> = BoxStream<'a, Result<(IpAddr, Details), Error>>;

/// All builtin resolvers.
pub const ALL: &dyn crate::Resolver = &&[
    #[cfg(feature = "dns-resolver")]
    dns::ALL,
    #[cfg(feature = "http-resolver")]
    http::ALL,
];

/// The version of IP address to resolve.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Version {
    V4,
    V6,
    Any,
}

impl Version {
    pub fn matches(self, addr: IpAddr) -> bool {
        self == Version::Any
            || (self == Version::V4 && addr.is_ipv4())
            || (self == Version::V6 && addr.is_ipv6())
    }
}

///////////////////////////////////////////////////////////////////////////////

/// Attempts to produce an IP address with all builtin resolvers (best effort).
///
/// This function will attempt to resolve until the stream is empty and will
/// drop/ignore any resolver errors.
pub async fn addr() -> Option<IpAddr> {
    addr_with(ALL, Version::Any).await
}

/// Attempts to produce an IPv4 address with all builtin resolvers (best
/// effort).
///
/// This function will attempt to resolve until the stream is empty and will
/// drop/ignore any resolver errors.
pub async fn addr_v4() -> Option<Ipv4Addr> {
    addr_with(ALL, Version::V4).await.map(|addr| match addr {
        IpAddr::V4(addr) => addr,
        IpAddr::V6(_) => unreachable!(),
    })
}

/// Attempts to produce an IPv6 address with all builtin resolvers (best
/// effort).
///
/// This function will attempt to resolve until the stream is empty and will
/// drop/ignore any resolver errors.
pub async fn addr_v6() -> Option<Ipv6Addr> {
    addr_with(ALL, Version::V6).await.map(|addr| match addr {
        IpAddr::V6(addr) => addr,
        IpAddr::V4(_) => unreachable!(),
    })
}

/// Given a [`Resolver`] and requested [`Version`], attempts to produce an IP
/// address (best effort).
///
/// This function will attempt to resolve until the stream is empty and will
/// drop/ignore any resolver errors.
pub async fn addr_with(resolver: impl Resolver<'_>, version: Version) -> Option<IpAddr> {
    addr_with_details(resolver, version)
        .await
        .map(|(addr, _)| addr)
}

/// Given a [`Resolver`] and requested [`Version`], attempts to produce an IP
/// address along with the details of how it was resolved (best effort).
///
/// This function will attempt to resolve until the stream is empty and will
/// drop/ignore any resolver errors.
pub async fn addr_with_details(
    resolver: impl Resolver<'_>,
    version: Version,
) -> Option<(IpAddr, Details)> {
    resolve(resolver, version)
        .filter_map(|result| future::ready(result.ok()))
        .next()
        .await
}

/// Given a [`Resolver`] and requested [`Version`], produces a stream of [`Resolutions`].
///
/// This function also protects against a resolver returning a IP address with a
/// version that was not requested.
pub fn resolve<'r>(resolver: impl Resolver<'r>, version: Version) -> Resolutions<'r> {
    Box::pin(resolver.resolve(version).and_then(move |(addr, details)| {
        // If a resolver returns a version not matching the one we requested
        // this is an error so it is skipped.
        let result = if version.matches(addr) {
            Ok((addr, details))
        } else {
            Err(Error::Version)
        };
        future::ready(result)
    }))
}

///////////////////////////////////////////////////////////////////////////////

/// Trait implemented by IP address resolver.
pub trait Resolver<'a>: Send + Sync {
    /// Resolves a stream of IP addresses with a given [`Version`].
    fn resolve(&self, version: Version) -> Resolutions<'a>;
}

impl<'r> Resolver<'r> for &'r dyn Resolver<'r> {
    fn resolve(&self, version: Version) -> Resolutions<'r> {
        (**self).resolve(version)
    }
}

impl<'r, R> Resolver<'r> for &'r [R]
where
    R: Resolver<'r>,
{
    fn resolve(&self, version: Version) -> Resolutions<'r> {
        pin_project! {
            struct DynSliceResolver<'r, R> {
                version: Version,
                resolvers: slice::Iter<'r, R>,
                #[pin]
                stream: Resolutions<'r>,
            }
        }

        impl<'r, R> Stream for DynSliceResolver<'r, R>
        where
            R: Resolver<'r>,
        {
            type Item = Result<(IpAddr, Details), Error>;

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                match ready!(self.as_mut().project().stream.poll_next(cx)) {
                    Some(o) => Poll::Ready(Some(o)),
                    None => {
                        if let Some(next) = self.resolvers.next() {
                            self.stream = next.resolve(self.version);
                            self.project().stream.poll_next(cx)
                        } else {
                            Poll::Ready(None)
                        }
                    }
                }
            }
        }

        let mut resolvers = self.iter();

        let stream = match resolvers.next() {
            Some(first) => first.resolve(version),
            None => Box::pin(stream::empty()),
        };

        let resolver = DynSliceResolver {
            version,
            resolvers,
            stream,
        };

        Box::pin(resolver)
    }
}

macro_rules! resolver_array {
    () => {
        resolver_array!(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
        );
    };
    ($($n:expr),*) => {
        $(
            impl<'r> Resolver<'r> for &'r [&'r dyn Resolver<'r>; $n] {
                fn resolve(&self, version: Version) -> Resolutions<'r> {
                    Resolver::resolve(&&self[..], version)
                }
            }
        )*
    }
}

resolver_array!();
