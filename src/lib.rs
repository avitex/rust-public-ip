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
use std::net::IpAddr;
use std::pin::Pin;
use std::slice;
use std::task::{Context, Poll};

use futures_core::Stream;
use futures_util::ready;
use futures_util::stream::{self, BoxStream, StreamExt};
use pin_project_lite::pin_project;

pub use crate::error::Error;

pub type Details = Box<dyn Any + Send + Sync + 'static>;
pub type Resolutions<'a> = BoxStream<'a, Result<(IpAddr, Details), Error>>;

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

/// Attempts resolve a single address (best effort)
pub async fn resolve_address(resolver: impl Resolver<'_>, version: Version) -> Option<IpAddr> {
    resolve_details(resolver, version)
        .await
        .map(|(addr, _)| addr)
}

/// Attempts to resolve to a resolution (best effort)
pub async fn resolve_details(
    resolver: impl Resolver<'_>,
    version: Version,
) -> Option<(IpAddr, Details)> {
    let mut resolution_stream = resolver.resolve(version);
    loop {
        match resolution_stream.next().await {
            Some(Ok(resolution)) => return Some(resolution),
            Some(Err(_)) => continue,
            None => return None,
        }
    }
}

pub fn resolve_stream<'r>(resolver: impl Resolver<'r>, version: Version) -> Resolutions<'r> {
    resolver.resolve(version)
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
