use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str;
use std::task::{Context, Poll};

use futures_core::Stream;
use futures_util::ready;
use futures_util::{future, stream};
use pin_project_lite::pin_project;
use trust_dns_proto::{
    error::{ProtoError, ProtoErrorKind},
    op::Query,
    rr::{Name, RData, RecordType},
    udp::UdpClientStream,
    xfer::{DnsHandle, DnsRequestOptions, DnsResponse},
};

#[cfg(feature = "tokio-dns-resolver")]
use tokio::{net::UdpSocket, runtime::Handle};
#[cfg(feature = "tokio-dns-resolver")]
use trust_dns_client::client::AsyncClient;

use crate::{Resolutions, Version};

///////////////////////////////////////////////////////////////////////////////
// Hardcoded resolvers

const DEFAULT_DNS_PORT: u16 = 53;

/// All builtin DNS resolvers.
pub const ALL: &dyn crate::Resolver<'static> = &&[
    #[cfg(feature = "opendns")]
    OPENDNS,
    #[cfg(feature = "google")]
    GOOGLE,
];

/// Combined OpenDNS IPv4 and IPv6 options.
#[cfg(feature = "opendns")]
#[cfg_attr(docsrs, doc(cfg(feature = "opendns")))]
pub const OPENDNS: &dyn crate::Resolver<'static> = &&[OPENDNS_V4, OPENDNS_V6];

/// OpenDNS IPv4 DNS resolver options.
#[cfg(feature = "opendns")]
#[cfg_attr(docsrs, doc(cfg(feature = "opendns")))]
pub const OPENDNS_V4: &dyn crate::Resolver<'static> = &Resolver::new_static(
    "myip.opendns.com",
    &[
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 220)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 222)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::A,
);

/// OpenDNS IPv6 DNS resolver options.
#[cfg(feature = "opendns")]
#[cfg_attr(docsrs, doc(cfg(feature = "opendns")))]
pub const OPENDNS_V6: &dyn crate::Resolver<'static> = &Resolver::new_static(
    "myip.opendns.com",
    &[
        // 2620:0:ccc::2
        IpAddr::V6(Ipv6Addr::new(9760, 0, 3276, 0, 0, 0, 0, 2)),
        // 2620:0:ccd::2
        IpAddr::V6(Ipv6Addr::new(9760, 0, 3277, 0, 0, 0, 0, 2)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::AAAA,
);

/// Combined Google DNS IPv4 and IPv6 options
#[cfg(feature = "google")]
#[cfg_attr(docsrs, doc(cfg(feature = "google")))]
pub const GOOGLE: &dyn crate::Resolver<'static> = &&[GOOGLE_V4, GOOGLE_V6];

/// Google DNS IPv4 DNS resolver options
#[cfg(feature = "google")]
#[cfg_attr(docsrs, doc(cfg(feature = "google")))]
pub const GOOGLE_V4: &dyn crate::Resolver<'static> = &Resolver::new_static(
    "o-o.myaddr.l.google.com",
    &[
        IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 34, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 36, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 38, 10)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::TXT,
);

/// Google DNS IPv6 DNS resolver options
#[cfg(feature = "google")]
#[cfg_attr(docsrs, doc(cfg(feature = "google")))]
pub const GOOGLE_V6: &dyn crate::Resolver<'static> = &Resolver::new_static(
    "o-o.myaddr.l.google.com",
    &[
        // 2001:4860:4802:32::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 50, 0, 0, 0, 10)),
        // 2001:4860:4802:34::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 52, 0, 0, 0, 10)),
        // 2001:4860:4802:36::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 54, 0, 0, 0, 10)),
        // 2001:4860:4802:38::a
        IpAddr::V6(Ipv6Addr::new(8193, 18528, 18434, 56, 0, 0, 0, 10)),
    ],
    DEFAULT_DNS_PORT,
    QueryMethod::TXT,
);

///////////////////////////////////////////////////////////////////////////////
// Error

/// DNS resolver error.
pub type Error = ProtoError;

///////////////////////////////////////////////////////////////////////////////
// Details & options

/// Details produced from a DNS resolution.
#[derive(Debug, Clone)]
pub struct Details {
    server: SocketAddr,
    name: Name,
    method: QueryMethod,
}

impl Details {
    /// DNS name used in the resolution of our IP address.
    #[must_use]
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// DNS server used in the resolution of our IP address.
    #[must_use]
    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// The query method used in the resolution of our IP address.
    #[must_use]
    pub fn query_method(&self) -> QueryMethod {
        self.method
    }
}

/// Method used to query an IP address from a DNS server
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QueryMethod {
    /// The first queried `A` name record is extracted as our IP address.
    A,
    /// The first queried `AAAA` name record is extracted as our IP address.
    AAAA,
    /// The first `TXT` record is extracted and parsed as our IP address.
    TXT,
}

///////////////////////////////////////////////////////////////////////////////
// Resolver

/// Options to build a DNS resolver.
#[derive(Debug)]
pub struct Resolver<'r> {
    port: u16,
    name: Cow<'r, str>,
    servers: Cow<'r, [IpAddr]>,
    method: QueryMethod,
}

impl<'r> Resolver<'r> {
    /// Create a new DNS resolver.
    pub fn new<N, S>(name: N, servers: S, port: u16, method: QueryMethod) -> Self
    where
        N: Into<Cow<'r, str>>,
        S: Into<Cow<'r, [IpAddr]>>,
    {
        Self {
            port,
            name: name.into(),
            servers: servers.into(),
            method,
        }
    }
}

impl Resolver<'static> {
    /// Create a new DNS resolver from static options.
    #[must_use]
    pub const fn new_static(
        name: &'static str,
        servers: &'static [IpAddr],
        port: u16,
        method: QueryMethod,
    ) -> Self {
        Self {
            port,
            name: Cow::Borrowed(name),
            servers: Cow::Borrowed(servers),
            method,
        }
    }
}

impl<'r> crate::Resolver<'r> for Resolver<'r> {
    fn resolve(&self, version: Version) -> Resolutions<'r> {
        let port = self.port;
        let method = self.method;
        let name = match Name::from_ascii(self.name.as_ref()) {
            Ok(name) => name,
            Err(err) => return Box::pin(stream::once(future::ready(Err(crate::Error::new(err))))),
        };
        let mut servers: Vec<_> = self
            .servers
            .iter()
            .copied()
            .filter(|addr| version.matches(*addr))
            .collect();
        let first_server = match servers.pop() {
            Some(server) => server,
            None => return Box::pin(stream::empty()),
        };
        let record_type = match self.method {
            QueryMethod::A => RecordType::A,
            QueryMethod::AAAA => RecordType::AAAA,
            QueryMethod::TXT => RecordType::TXT,
        };
        let query = Query::query(name, record_type);
        let stream = resolve(first_server, port, query.clone(), method);
        Box::pin(DnsResolutions {
            port,
            version,
            query,
            method,
            servers,
            stream,
        })
    }
}

///////////////////////////////////////////////////////////////////////////////
// Resolutions

pin_project! {
    struct DnsResolutions<'r> {
        port: u16,
        version: Version,
        query: Query,
        method: QueryMethod,
        servers: Vec<IpAddr>,
        #[pin]
        stream: Resolutions<'r>,
    }
}

impl<'r> Stream for DnsResolutions<'r> {
    type Item = Result<(IpAddr, crate::Details), crate::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(self.as_mut().project().stream.poll_next(cx)) {
            Some(o) => Poll::Ready(Some(o)),
            None => self.servers.pop().map_or(Poll::Ready(None), |server| {
                self.stream = resolve(server, self.port, self.query.clone(), self.method);
                self.project().stream.poll_next(cx)
            }),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
// Client

#[cfg(feature = "tokio-dns-resolver")]
async fn dns_query(
    server: SocketAddr,
    query: Query,
    query_opts: DnsRequestOptions,
) -> Result<DnsResponse, ProtoError> {
    let handle = Handle::current();
    let stream = UdpClientStream::<UdpSocket>::new(server);
    let (mut client, bg) = AsyncClient::connect(stream).await?;
    handle.spawn(bg);
    client.lookup(query, query_opts).await
}

fn parse_dns_response(
    mut response: DnsResponse,
    method: QueryMethod,
) -> Result<IpAddr, crate::Error> {
    let answer = match response.take_answers().into_iter().next() {
        Some(answer) => answer,
        None => return Err(crate::Error::Addr),
    };
    match answer.into_data() {
        RData::A(addr) if method == QueryMethod::A => Ok(IpAddr::V4(addr)),
        RData::AAAA(addr) if method == QueryMethod::AAAA => Ok(IpAddr::V6(addr)),
        RData::TXT(txt) if method == QueryMethod::TXT => match txt.iter().next() {
            Some(addr_bytes) => Ok(str::from_utf8(&addr_bytes[..])?.parse()?),
            None => Err(crate::Error::Addr),
        },
        _ => Err(ProtoError::from(ProtoErrorKind::Message("invalid response")).into()),
    }
}

fn resolve<'r>(server: IpAddr, port: u16, query: Query, method: QueryMethod) -> Resolutions<'r> {
    let fut = async move {
        let name = query.name().clone();
        let server = SocketAddr::new(server, port);
        let query_opts = DnsRequestOptions {
            use_edns: true,
            expects_multiple_responses: false,
        };
        let response = dns_query(server, query, query_opts).await?;
        let addr = parse_dns_response(response, method)?;
        let details = Box::new(Details {
            name,
            method,
            server,
        });
        Ok((addr, crate::Details::from(details)))
    };
    Box::pin(stream::once(fut))
}
