//! Crate providing a generic way to find the public IP address of the
//! device it runs on, along with with some built in resolvers
//!
//! # Basic Usage
//!
//! ```rust
//! use async_std::task;
//! use public_ip::{dns, http, ToResolver, BoxToResolver};
//!
//! // List of resolvers to try and get an IP address from
//! let resolver = vec![
//!     BoxToResolver::new(dns::OPENDNS_RESOLVER),
//!     BoxToResolver::new(http::HTTP_IPIFY_ORG_RESOLVER),
//! ].to_resolver();
//! // Attempt to get an IP address and print it
//! if let Some(ip) = task::block_on(public_ip::resolve_address(resolver)) {
//!     println!("public ip address: {:?}", ip);
//! } else {
//!     println!("couldn't get an IP address");
//! }
//! ```
//!
//! # Usage with Resolution
//!
//! ```rust
//! use std::any::Any;
//!
//! use async_std::task;
//! use public_ip::{dns, ToResolver, Resolution};
//!  
//! // List of resolvers to try and get an IP address from
//! let resolver = dns::OPENDNS_RESOLVER.to_resolver();
//! // Attempt to get an IP address and print it
//! if let Some(resolution) = task::block_on(public_ip::resolve(resolver)) {
//!     if let Some(resolution) = Any::downcast_ref::<dns::DnsResolution>(&resolution) {
//!         println!("public ip address {:?} resolved from {:?} ({:?})",
//!             resolution.address(),
//!             resolution.name(),
//!             resolution.server(),
//!         );
//!     }
//! } else {
//!     println!("couldn't get an IP address");
//! }
//! ```

mod resolver;

#[cfg(any(feature = "http-resolver", feature = "dns-resolver"))]
mod util;

#[cfg(feature = "dns-resolver")]
pub mod dns;

#[cfg(feature = "http-resolver")]
pub mod http;

use std::any::Any;
use std::fmt::Debug;
use std::net::IpAddr;

use futures::stream::{BoxStream, StreamExt};

pub use crate::resolver::*;

/// Boxed `dyn Resolution`
pub type BoxResolution = Box<dyn Resolution>;
/// Boxed `dyn ResolutionError`
pub type BoxResolutionError = Box<dyn ResolutionError>;
/// Boxed `dyn Stream<Item = Result<BoxResolution, BoxResolutionError>>`
pub type BoxResolutionStream = BoxStream<'static, Result<BoxResolution, BoxResolutionError>>;

///////////////////////////////////////////////////////////////////////////////

/// The successful product of a resolver
///
/// As well as containing the IP address resolved,
/// resolvers will contain the specific parameters
/// used in the resolution in their concrete type.
/// Using `Any` allows you to downcast them to the
/// specific type and retrive them.
pub trait Resolution: Send + Any {
    /// The IP address resolved
    fn address(&self) -> IpAddr;
}

impl Resolution for Box<dyn Resolution> {
    fn address(&self) -> IpAddr {
        self.as_ref().address()
    }
}

///////////////////////////////////////////////////////////////////////////////

/// An error produced while attempting to resolve
pub trait ResolutionError: Send + Any + Debug {}

impl<T> ResolutionError for T where T: Send + Any + Debug {}

///////////////////////////////////////////////////////////////////////////////

/// Attempts resolve a single address (best effort)
pub async fn resolve_address<R>(resolver: R) -> Option<IpAddr>
where
    R: Resolver<DefaultResolverContext> + Unpin,
    R::Stream: Unpin,
{
    resolve(resolver).await.as_ref().map(Resolution::address)
}

/// Attempts to resolve to a resolution (best effort)
pub async fn resolve<R>(resolver: R) -> Option<R::Resolution>
where
    R: Resolver<DefaultResolverContext> + Unpin,
    R::Stream: Unpin,
{
    let mut resolution_stream = resolve_stream(resolver);
    loop {
        match resolution_stream.next().await {
            Some(Ok(resolution)) => return Some(resolution),
            Some(Err(_)) => continue,
            None => return None,
        }
    }
}

/// Resolves a stream with a default context
pub fn resolve_stream<R>(mut resolver: R) -> R::Stream
where
    R: Resolver<DefaultResolverContext>,
{
    (&mut resolver).resolve(DefaultResolverContext)
}
