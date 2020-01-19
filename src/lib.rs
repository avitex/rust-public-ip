mod resolver;

#[cfg(any(feature = "http-resolver", feature = "dns-resolver"))]
mod util;

#[cfg(feature = "dns-resolver")]
pub mod dns;

#[cfg(feature = "http-resolver")]
pub mod http;

use std::any::Any;
use std::convert::identity;
use std::fmt::Debug;
use std::net::IpAddr;

use futures::stream::{BoxStream, StreamExt};

pub use crate::resolver::*;

pub type BoxResolution = Box<dyn Resolution>;
pub type BoxResolutionError = Box<dyn ResolutionError>;
pub type BoxResolutionStream = BoxStream<'static, Result<BoxResolution, BoxResolutionError>>;

///////////////////////////////////////////////////////////////////////////////

pub trait Resolution: Send + Any {
    fn address(&self) -> IpAddr;
}

impl Resolution for Box<dyn Resolution> {
    fn address(&self) -> IpAddr {
        self.as_ref().address()
    }
}

///////////////////////////////////////////////////////////////////////////////

pub trait ResolutionError: Send + Any + Debug {}

impl<T> ResolutionError for T where T: Send + Any + Debug {}

///////////////////////////////////////////////////////////////////////////////

pub async fn resolve_address<R>(resolver: R) -> Option<IpAddr>
where
    R: Resolver<DefaultResolverContext> + Unpin,
    R::Stream: Unpin,
{
    resolve(resolver)
        .await
        .ok()
        .and_then(identity)
        .as_ref()
        .map(Resolution::address)
}

pub async fn resolve<R>(resolver: R) -> Result<Option<R::Resolution>, R::Error>
where
    R: Resolver<DefaultResolverContext> + Unpin,
    R::Stream: Unpin,
{
    resolve_stream(resolver).next().await.transpose()
}

pub fn resolve_stream<R>(mut resolver: R) -> R::Stream
where
    R: Resolver<DefaultResolverContext>,
{
    (&mut resolver).resolve(DefaultResolverContext)
}
