use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{mem, str};

use futures::future::{self, FutureExt, TryFutureExt};
use futures::stream::{self, BoxStream, StreamExt};
use tokio::net::UdpSocket;
use trust_dns_client::{
    client::AsyncClient as AsyncDnsClient,
    op::{DnsResponse, Query as DnsQuery},
    rr::{Name as DnsName, RData as DnsRData, RecordType as DnsRecordType},
    udp::UdpClientStream,
};
use trust_dns_proto::{
    error::ProtoError as DnsProtoError,
    xfer::{DnsHandle, DnsRequestOptions},
};

use crate::{
    util, AutoResolverContext, Resolution, Resolver, ResolverContext, ResultResolver, ToResolver,
};

const DNS_SOCKET_PORT: u16 = 53;

///////////////////////////////////////////////////////////////////////////////
// Hardcoded DNS resolvers

/// Combined OpenDNS IPv4 and IPv6 options
pub const OPENDNS_RESOLVER: &[DnsResolverOptions] = &[OPENDNS_RESOLVER_V4, OPENDNS_RESOLVER_V6];

/// OpenDNS IPv4 DNS resolver options
pub const OPENDNS_RESOLVER_V4: DnsResolverOptions = DnsResolverOptions::new_static(
    "myip.opendns.com",
    &[
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 222, 220)),
        IpAddr::V4(Ipv4Addr::new(208, 67, 220, 222)),
    ],
    QueryMethod::A,
);

/// OpenDNS IPv6 DNS resolver options
pub const OPENDNS_RESOLVER_V6: DnsResolverOptions = DnsResolverOptions::new_static(
    "myip.opendns.com",
    &[
        // 2620:0:ccc::2
        IpAddr::V6(Ipv6Addr::new(9760, 0, 3276, 0, 0, 0, 0, 2)),
        // 2620:0:ccd::2
        IpAddr::V6(Ipv6Addr::new(9760, 0, 3277, 0, 0, 0, 0, 2)),
    ],
    QueryMethod::AAAA,
);

/// Combined Google DNS IPv4 and IPv6 options
pub const GOOGLE_DNS_TXT_RESOLVER: &[DnsResolverOptions] =
    &[GOOGLE_DNS_TXT_RESOLVER_V4, GOOGLE_DNS_TXT_RESOLVER_V6];

/// Google DNS IPv4 DNS resolver options
pub const GOOGLE_DNS_TXT_RESOLVER_V4: DnsResolverOptions = DnsResolverOptions::new_static(
    "o-o.myaddr.l.google.com",
    &[
        IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 34, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 36, 10)),
        IpAddr::V4(Ipv4Addr::new(216, 239, 38, 10)),
    ],
    QueryMethod::TXT,
);

/// Google DNS IPv6 DNS resolver options
pub const GOOGLE_DNS_TXT_RESOLVER_V6: DnsResolverOptions = DnsResolverOptions::new_static(
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
    QueryMethod::TXT,
);

///////////////////////////////////////////////////////////////////////////////
// DNS client support

async fn query_dns_server(
    rt: &util::TokioRuntime,
    host: IpAddr,
    query: DnsQuery,
) -> Result<DnsResponse, DnsProtoError> {
    let addr = SocketAddr::new(host, DNS_SOCKET_PORT);
    let stream = UdpClientStream::<UdpSocket>::new(addr);
    let (mut client, bg) = AsyncDnsClient::connect(stream).await?;
    rt.spawn(bg);
    let query_opts = DnsRequestOptions {
        expects_multiple_responses: false,
    };
    client.lookup(query, query_opts).await
}

fn parse_dns_response(
    mut response: DnsResponse,
    method: QueryMethod,
) -> Result<IpAddr, DnsResolutionError> {
    let answer = match response.take_answers().into_iter().next() {
        Some(answer) => answer,
        None => return Err(DnsResolutionError::EmptyIpAddr),
    };
    match answer.unwrap_rdata() {
        DnsRData::A(addr) if method == QueryMethod::A => Ok(IpAddr::V4(addr)),
        DnsRData::AAAA(addr) if method == QueryMethod::AAAA => Ok(IpAddr::V6(addr)),
        DnsRData::TXT(txt) if method == QueryMethod::TXT => match txt.iter().next() {
            Some(addr_bytes) => {
                if let Ok(addr_str) = str::from_utf8(&addr_bytes[..]) {
                    if let Ok(addr) = addr_str.parse() {
                        return Ok(addr);
                    }
                }
                Err(DnsResolutionError::InvalidIpAddr)
            }
            None => Err(DnsResolutionError::EmptyIpAddr),
        },
        _ => Err(DnsResolutionError::InvalidResponse),
    }
}

///////////////////////////////////////////////////////////////////////////////

/// An error produced from a DNS resolver
#[derive(Debug)]
pub enum DnsResolutionError {
    Proto(DnsProtoError),
    InvalidIpAddr,
    InvalidResponse,
    InvalidDnsName,
    EmptyIpAddr,
}

/// Method used to query an IP address from a DNS server
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum QueryMethod {
    A,
    AAAA,
    TXT,
}

/// Options to build a DNS resolver
pub struct DnsResolverOptions<'a> {
    name: Cow<'a, str>,
    servers: Cow<'a, [IpAddr]>,
    method: QueryMethod,
}

impl<'a> DnsResolverOptions<'a> {
    /// Create new DNS resolver options
    pub fn new<N, S>(name: N, servers: S, method: QueryMethod) -> Self
    where
        N: Into<Cow<'a, str>>,
        S: Into<Cow<'a, [IpAddr]>>,
    {
        Self {
            name: name.into(),
            servers: servers.into(),
            method,
        }
    }
}

impl DnsResolverOptions<'static> {
    /// Create new DNS resolver options from static
    pub const fn new_static(
        name: &'static str,
        servers: &'static [IpAddr],
        method: QueryMethod,
    ) -> Self {
        Self {
            name: Cow::Borrowed(name),
            servers: Cow::Borrowed(servers),
            method,
        }
    }
}

impl<'a, C> ToResolver<C> for DnsResolverOptions<'a>
where
    C: DnsResolverContext,
{
    type Resolver = ResultResolver<DnsResolver, DnsResolutionError>;

    fn to_resolver(&self) -> Self::Resolver {
        let result = DnsResolver::new(self.name.to_string(), self.servers.to_vec(), self.method);
        ResultResolver::new(result)
    }
}

/// A resolution produced from a DNS resolver
#[derive(Clone, Debug)]
pub struct DnsResolution {
    address: IpAddr,
    server: IpAddr,
    name: DnsName,
    method: QueryMethod,
}

impl DnsResolution {
    /// DNS name used in the resolution of the associated IP address
    pub fn name(&self) -> &DnsName {
        &self.name
    }

    /// DNS server used in the resolution of the associated IP address
    pub fn server(&self) -> IpAddr {
        self.server
    }

    /// The query method used in the resolution of the associated IP address
    pub fn query_method(&self) -> QueryMethod {
        self.method
    }
}

impl Resolution for DnsResolution {
    fn address(&self) -> IpAddr {
        self.address
    }
}

/// The DNS resolver
#[derive(Clone, Debug)]
pub struct DnsResolver {
    query: DnsQuery,
    servers: Vec<IpAddr>,
    method: QueryMethod,
}

impl DnsResolver {
    /// Create new DNS resolver
    pub fn new<N, I>(name: N, servers: I, method: QueryMethod) -> Result<Self, DnsResolutionError>
    where
        N: Into<Cow<'static, str>>,
        I: IntoIterator<Item = IpAddr>,
    {
        let servers = servers.into_iter().collect();
        let record_type = match method {
            QueryMethod::A => DnsRecordType::A,
            QueryMethod::AAAA => DnsRecordType::AAAA,
            QueryMethod::TXT => DnsRecordType::TXT,
        };
        let name =
            DnsName::from_ascii(name.into()).map_err(|_| DnsResolutionError::InvalidDnsName)?;
        let query = DnsQuery::query(name, record_type);
        Ok(Self {
            query,
            servers,
            method,
        })
    }
}

impl<C> Resolver<C> for DnsResolver
where
    C: DnsResolverContext,
{
    type Error = DnsResolutionError;
    type Stream = BoxStream<'static, Result<Self::Resolution, Self::Error>>;
    type Resolution = DnsResolution;

    fn resolve(&mut self, cx: C) -> Self::Stream {
        let runtime = cx.runtime();
        let mut servers = Vec::new();
        let query = self.query.clone();
        let method = self.method;
        mem::swap(&mut servers, &mut self.servers);
        let queries = servers
            .into_iter()
            .map(move |server| (server, query.clone(), method));

        let stream = stream::iter(queries).then(move |(server, query, method)| {
            let name = query.name().clone();
            let query_fut = query_dns_server(runtime, server, query)
                .map_err(DnsResolutionError::Proto)
                .and_then(move |r| future::ready(parse_dns_response(r, method)))
                .map_ok(move |address| DnsResolution {
                    name,
                    method,
                    server,
                    address,
                });

            runtime
                .spawn(query_fut)
                .map(|res| res.expect("failed to execute query future"))
        });
        Box::pin(stream)
    }
}

/// Context used in a DNS resolver
pub trait DnsResolverContext: ResolverContext {
    fn runtime<'a>(&self) -> &'a util::TokioRuntime {
        util::tokio_runtime()
    }
}

impl<T> DnsResolverContext for T where T: AutoResolverContext {}
