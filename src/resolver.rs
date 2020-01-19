use std::marker::PhantomData;
use std::mem;

use futures::future;
use futures::stream::{self, BoxStream, Stream, StreamExt, TryStreamExt};

use crate::{BoxResolution, BoxResolutionError, BoxResolutionStream, Resolution, ResolutionError};

pub trait Resolver<C: ResolverContext>: Send {
    type Error: ResolutionError;
    type Resolution: Resolution;
    type Stream: Stream<Item = Result<Self::Resolution, Self::Error>> + Send + 'static;

    fn resolve(&mut self, cx: C) -> Self::Stream;
}

///////////////////////////////////////////////////////////////////////////////

pub trait ResolverContext: Send {}

pub trait AutoResolverContext: ResolverContext {}

#[derive(Clone)]
pub struct DefaultResolverContext;

impl ResolverContext for DefaultResolverContext {}
impl AutoResolverContext for DefaultResolverContext {}

///////////////////////////////////////////////////////////////////////////////

type BoxResolverInner<C> = Box<
    dyn Resolver<
        C,
        Resolution = BoxResolution,
        Error = BoxResolutionError,
        Stream = BoxResolutionStream,
    >,
>;

pub struct BoxResolver<C> {
    inner: BoxResolverInner<C>,
}

impl<C> BoxResolver<C>
where
    C: ResolverContext,
{
    pub fn new<R>(resolver: R) -> Self
    where
        R: Resolver<C> + 'static,
    {
        let wrapped = DynResolverWrapper(resolver);
        let inner = Box::new(wrapped) as BoxResolverInner<C>;
        Self { inner }
    }
}

impl<C> Resolver<C> for BoxResolver<C>
where
    C: ResolverContext,
{
    type Error = BoxResolutionError;
    type Resolution = BoxResolution;
    type Stream = BoxResolutionStream;

    fn resolve(&mut self, cx: C) -> Self::Stream {
        self.inner.resolve(cx)
    }
}

struct DynResolverWrapper<R>(R);

impl<C, R> Resolver<C> for DynResolverWrapper<R>
where
    R: Resolver<C>,
    C: ResolverContext,
{
    type Error = BoxResolutionError;
    type Resolution = BoxResolution;
    type Stream = BoxResolutionStream;

    fn resolve(&mut self, cx: C) -> Self::Stream {
        let stream = self
            .0
            .resolve(cx)
            .map_ok(|o| Box::new(o) as Self::Resolution)
            .map_err(|o| Box::new(o) as Self::Error);

        Box::pin(stream)
    }
}

///////////////////////////////////////////////////////////////////////////////

pub struct ResultResolver<R, E> {
    inner: Option<Result<R, E>>,
}

impl<R, E> ResultResolver<R, E> {
    pub fn new(result: Result<R, E>) -> Self {
        Self {
            inner: Some(result),
        }
    }
}

impl<R, E, C> Resolver<C> for ResultResolver<R, E>
where
    R: Resolver<C>,
    C: ResolverContext,
    E: ResolutionError,
{
    type Error = BoxResolutionError;
    type Resolution = R::Resolution;
    type Stream = BoxStream<'static, Result<Self::Resolution, Self::Error>>;

    fn resolve(&mut self, cx: C) -> Self::Stream {
        match self.inner.take().expect("resolver resolve called twice") {
            Ok(mut r) => {
                let stream = r.resolve(cx).map_err(|o| Box::new(o) as Self::Error);
                Box::pin(stream)
            }
            Err(e) => {
                let err = Box::new(e) as Self::Error;
                Box::pin(stream::once(future::err(err)))
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

pub trait ToResolver<C>
where
    C: ResolverContext,
{
    type Resolver: Resolver<C>;

    fn to_resolver(&self) -> Self::Resolver;
}

impl<C, T> ToResolver<C> for &T
where
    T: ToResolver<C>,
    C: ResolverContext,
{
    type Resolver = T::Resolver;

    fn to_resolver(&self) -> Self::Resolver {
        (&**self).to_resolver()
    }
}

///////////////////////////////////////////////////////////////////////////////

type BoxToResolverInner<C> = Box<dyn ToResolver<C, Resolver = BoxResolver<C>>>;

pub struct BoxToResolver<C> {
    inner: BoxToResolverInner<C>,
}

impl<C> BoxToResolver<C> {
    pub fn new<R>(resolver: R) -> Self
    where
        R: ToResolver<C> + 'static,
        R::Resolver: 'static,
        C: ResolverContext,
    {
        let wrapped = DynToResolverWrapper(resolver);
        let inner = Box::new(wrapped) as BoxToResolverInner<C>;
        Self { inner }
    }
}

impl<C> ToResolver<C> for BoxToResolver<C>
where
    C: ResolverContext,
{
    type Resolver = BoxResolver<C>;

    fn to_resolver(&self) -> Self::Resolver {
        self.inner.to_resolver()
    }
}

struct DynToResolverWrapper<T>(T);

impl<C, T> ToResolver<C> for DynToResolverWrapper<T>
where
    T: ToResolver<C>,
    T::Resolver: 'static,
    C: ResolverContext,
{
    type Resolver = BoxResolver<C>;

    fn to_resolver(&self) -> Self::Resolver {
        BoxResolver::new(self.0.to_resolver())
    }
}

///////////////////////////////////////////////////////////////////////////////

impl<'a, T, C> ToResolver<C> for &'a [T]
where
    T: ToResolver<C>,
    T::Resolver: 'static,
    C: ResolverContext + Clone + 'static,
{
    type Resolver = ResolverList<T::Resolver, C>;

    fn to_resolver(&self) -> Self::Resolver {
        let resolvers = self.iter().map(|r| r.to_resolver()).collect();
        ResolverList::new(resolvers)
    }
}

impl<T, C> ToResolver<C> for Vec<T>
where
    T: ToResolver<C>,
    T::Resolver: 'static,
    C: ResolverContext + Clone + 'static,
{
    type Resolver = ResolverList<T::Resolver, C>;

    fn to_resolver(&self) -> Self::Resolver {
        let resolvers = self.iter().map(|r| r.to_resolver()).collect();
        ResolverList::new(resolvers)
    }
}

///////////////////////////////////////////////////////////////////////////////

pub struct ResolverList<R, C>
where
    R: Resolver<C> + 'static,
    C: ResolverContext + Clone + 'static,
{
    resolvers: Vec<R>,
    context: PhantomData<C>,
}

impl<R, C> ResolverList<R, C>
where
    R: Resolver<C> + 'static,
    C: ResolverContext + Clone + 'static,
{
    pub fn new(resolvers: Vec<R>) -> Self {
        Self {
            resolvers,
            context: PhantomData,
        }
    }
}

impl<R, C> Resolver<C> for ResolverList<R, C>
where
    R: Resolver<C> + 'static,
    C: ResolverContext + Clone + 'static,
{
    type Error = R::Error;
    type Resolution = R::Resolution;
    type Stream = BoxStream<'static, Result<Self::Resolution, Self::Error>>;

    fn resolve(&mut self, cx: C) -> Self::Stream {
        let mut resolvers = Vec::<R>::with_capacity(self.resolvers.len());
        mem::swap(&mut resolvers, &mut self.resolvers);
        let stream = stream::iter(resolvers)
            .map(move |mut resolver| resolver.resolve(cx.clone()))
            .flatten();
        Box::pin(stream)
    }
}
