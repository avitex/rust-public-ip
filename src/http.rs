use std::borrow::Cow;
use std::convert::TryFrom;
use std::future::Future;
use std::net::IpAddr;
use std::str;

use futures::future::{self, FutureExt, TryFutureExt};
use futures::stream::{self, BoxStream};
use http::uri::{InvalidUri as InvalidUriError, Uri};
use hyper::{
    body::{self, Body, Buf},
    client::{Builder, Client, HttpConnector},
    rt::Executor,
};
use once_cell::sync::{Lazy, OnceCell};
use regex::Regex;

use crate::{
    util, AutoResolverContext, Resolution, Resolver, ResolverContext, ResultResolver, ToResolver,
};

///////////////////////////////////////////////////////////////////////////////

/// `http://api.ipify.org` HTTP resolver options
pub const HTTP_IPIFY_ORG_RESOLVER: HttpResolverOptions =
    HttpResolverOptions::new_static("http://api.ipify.org", ExtractMethod::PlainText);

/// `http://bot.whatismyipaddress.com` HTTP resolver options
pub const HTTP_WHATISMYIPADDRESS_COM_RESOLVER: HttpResolverOptions =
    HttpResolverOptions::new_static("http://bot.whatismyipaddress.com", ExtractMethod::PlainText);

///////////////////////////////////////////////////////////////////////////////

/// Internal HTTP client used by a HTTP resolver
pub type HttpClient = Client<HttpConnector, Body>;

/// Method used to extract an IP address from a http response
#[derive(Debug, Clone, Copy)]
pub enum ExtractMethod {
    PlainText,
    StripDoubleQuotes,
    ExtractJsonIpField,
}

/// An error produced from a HTTP resolver
#[derive(Debug)]
pub enum HttpResolutionError {
    Uri(InvalidUriError),
    Client(hyper::Error),
    EmptyIpAddr,
    InvalidIpAddr,
    InvalidUtf8,
}

/// Options to build a HTTP resolver
#[derive(Clone, Debug)]
pub struct HttpResolverOptions<'a> {
    uri: Cow<'a, str>,
    method: ExtractMethod,
}

impl<'a> HttpResolverOptions<'a> {
    /// Create new HTTP resolver options
    pub fn new<U>(uri: U, method: ExtractMethod) -> Self
    where
        U: Into<Cow<'a, str>>,
    {
        Self {
            uri: uri.into(),
            method,
        }
    }
}

impl HttpResolverOptions<'static> {
    /// Create new HTTP resolver options from static
    pub const fn new_static(uri: &'static str, method: ExtractMethod) -> Self {
        Self {
            uri: Cow::Borrowed(uri),
            method,
        }
    }
}

impl<'a, C> ToResolver<C> for HttpResolverOptions<'a>
where
    C: HttpResolverContext,
{
    type Resolver = ResultResolver<HttpResolver, HttpResolutionError>;

    fn to_resolver(&self) -> Self::Resolver {
        let result = Uri::try_from(self.uri.as_ref())
            .map_err(HttpResolutionError::Uri)
            .map(|uri| HttpResolver::new(uri, self.method));
        ResultResolver::new(result)
    }
}

/// A resolution produced from a HTTP resolver
#[derive(Clone, Debug)]
pub struct HttpResolution {
    address: IpAddr,
    uri: Uri,
    method: ExtractMethod,
}

impl HttpResolution {
    /// URI used in the resolution of the associated IP address
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The extract method used in the resolution of the associated IP address
    pub fn extract_method(&self) -> ExtractMethod {
        self.method
    }
}

impl Resolution for HttpResolution {
    fn address(&self) -> IpAddr {
        self.address
    }
}

/// The HTTP resolver
pub struct HttpResolver {
    uri: Uri,
    method: ExtractMethod,
}

impl HttpResolver {
    /// Create new HTTP resolver
    pub fn new(uri: Uri, method: ExtractMethod) -> Self {
        Self { uri, method }
    }
}

impl<C> Resolver<C> for HttpResolver
where
    C: HttpResolverContext,
{
    type Error = HttpResolutionError;
    type Resolution = HttpResolution;
    type Stream = BoxStream<'static, Result<Self::Resolution, Self::Error>>;

    fn resolve(&mut self, cx: C) -> Self::Stream {
        // Get client and tokio runtime
        let client = cx.client();
        let runtime = cx.runtime();
        let uri = self.uri.clone();
        let method = self.method;
        // Init JSON IP field regex
        static JSON_IP_FIELD_REGEX: Lazy<Regex> =
            Lazy::new(|| Regex::new(r#"(?i)"ip"\s*:\s*"(.+?)""#).expect("invalid regex"));

        let req_fut = client
            .get(uri.clone())
            .and_then(|res| body::aggregate(res.into_body()))
            .map_err(HttpResolutionError::Client)
            .map_ok(move |body| {
                let body_str =
                    str::from_utf8(body.bytes()).map_err(|_| HttpResolutionError::InvalidUtf8)?;
                let address_str_opt = match method {
                    ExtractMethod::PlainText => Some(body_str),
                    ExtractMethod::ExtractJsonIpField => (*JSON_IP_FIELD_REGEX)
                        .captures(body_str)
                        .and_then(|caps| caps.get(1))
                        .map(|cap| cap.as_str()),
                    ExtractMethod::StripDoubleQuotes => Some(body_str.trim_matches('"')),
                };
                address_str_opt
                    .ok_or(HttpResolutionError::EmptyIpAddr)
                    .and_then(|s| s.parse().map_err(|_| HttpResolutionError::InvalidIpAddr))
                    .map(|address| HttpResolution {
                        address,
                        uri,
                        method,
                    })
            })
            .and_then(future::ready);

        let fut = runtime
            .spawn(req_fut)
            .map(|res| res.expect("failed to execute request future"));

        Box::pin(stream::once(fut))
    }
}

///////////////////////////////////////////////////////////////////////////////
// HttpContext

static DEFAULT_HTTP_CLIENT: OnceCell<HttpClient> = OnceCell::new();

/// Context used in a HTTP resolver
pub trait HttpResolverContext: ResolverContext {
    fn client<'a>(&self) -> &'a HttpClient {
        let executor = TokioExecutor(self.runtime());
        DEFAULT_HTTP_CLIENT.get_or_init(|| Builder::default().executor(executor).build_http())
    }

    fn runtime<'a>(&self) -> &'a util::TokioRuntime {
        util::tokio_runtime()
    }
}

impl<T> HttpResolverContext for T where T: AutoResolverContext {}

///////////////////////////////////////////////////////////////////////////////
// Hyper executor wrapper

struct TokioExecutor<'a>(&'a util::TokioRuntime);

impl<'a, F> Executor<F> for TokioExecutor<'a>
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        self.0.spawn(fut);
    }
}
