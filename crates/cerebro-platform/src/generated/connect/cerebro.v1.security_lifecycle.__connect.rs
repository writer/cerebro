///Shorthand for `OwnedView<ListSecurityLifecycleRequestView<'static>>`.
pub type OwnedListSecurityLifecycleRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ListSecurityLifecycleResponseView<'static>>`.
pub type OwnedListSecurityLifecycleResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ResolveSecurityLifecycleFindingRequestView<'static>>`.
pub type OwnedResolveSecurityLifecycleFindingRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ResolveSecurityLifecycleFindingResponseView<'static>>`.
pub type OwnedResolveSecurityLifecycleFindingResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingResponseView<
        'static,
    >,
>;
impl ::connectrpc::Encodable<
    crate::rpc::proto::cerebro::v1::ListSecurityLifecycleResponse,
>
for crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::rpc::proto::cerebro::v1::ListSecurityLifecycleResponse,
>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
impl ::connectrpc::Encodable<
    crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingResponse,
>
for crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingResponseView<
    '_,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<
    crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingResponse,
>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingResponseView<
        'static,
    >,
> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self.reborrow(), codec)
    }
    /// An `OwnedView` still holds the buffer it was decoded from, so
    /// its large fields can be handed to the response body by
    /// reference count instead of copied. The bare view impl above
    /// cannot do this: it has borrows but no buffer to name.
    fn encode_segments(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::connectrpc::EncodedBody, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body_segments(
            self.reborrow(),
            self.bytes(),
            codec,
        )
    }
}
/// Full service name for this service.
pub const SECURITY_LIFECYCLE_SERVICE_SERVICE_NAME: &str = "cerebro.v1.SecurityLifecycleService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ListSecurityLifecycle` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const SECURITY_LIFECYCLE_SERVICE_LIST_SECURITY_LIFECYCLE_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.v1.SecurityLifecycleService/ListSecurityLifecycle",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ResolveSecurityLifecycleFinding` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const SECURITY_LIFECYCLE_SERVICE_RESOLVE_SECURITY_LIFECYCLE_FINDING_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.v1.SecurityLifecycleService/ResolveSecurityLifecycleFinding",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// SecurityLifecycleService exposes bounded lifecycle reads from the Rust
/// organizational platform.
///
/// # Implementing handlers
///
/// Implement methods with plain `async fn`; the returned future satisfies
/// the `Send` bound automatically.
///
/// **Unary and server-streaming requests** arrive as
/// [`ServiceRequest<'_, Req>`](::connectrpc::ServiceRequest): a zero-copy
/// view of the request plus its body, valid for the duration of the call.
/// Fields are read directly (`request.name` is a `&str` into the decoded
/// buffer) and the borrow may be held across `.await` points. Anything
/// that must outlive the call — `tokio::spawn`, channels, server state,
/// or data captured by a returned response stream — takes owned data:
/// call `request.to_owned_message()` (or copy the specific fields)
/// first.
///
/// **Client-streaming and bidi requests** arrive as
/// [`InboundStream<Req>`](::connectrpc::InboundStream) — a
/// `ServiceStream` of [`StreamMessage`](::connectrpc::StreamMessage)s.
/// Each item owns its decoded buffer and is `Send + 'static`, so items
/// can be buffered or moved into spawned tasks; read fields zero-copy
/// through the generated accessor methods (`item.name()`) or `.view()`,
/// convert with `.to_owned_message()`, or yield an item back unchanged —
/// `StreamMessage<M>` implements `Encodable<M>`.
///
/// Request types resolved through `extern_path` (e.g. well-known types
/// from another crate) use the same wrappers; the crate that owns the
/// type must be generated with buffa ≥ 0.9.0 and views enabled so the
/// backing `HasMessageView` impl exists.
///
/// The `impl Encodable<Out>` return bound accepts the owned `Out`, the
/// generated `OutView<'_>` / `OwnedOutView`,
/// [`MaybeBorrowed`](::connectrpc::MaybeBorrowed), or
/// [`PreEncoded`](::connectrpc::PreEncoded) for handlers that encode a
/// non-`'static` view internally and pass the bytes across the handler
/// boundary. View bodies are not emitted for output types mapped via
/// `extern_path` (the impl would be an orphan); return owned for
/// WKT/extern outputs.
///
/// Server-streaming and bidi-streaming methods return
/// `ServiceStream<impl Encodable<Out> + Send + use<Self>>`. The
/// `use<Self>` precise-capturing clause excludes `&self`'s lifetime and
/// the request's lifetime (unary methods use `use<'a, Self>` and may
/// borrow from `&self`), so stream items must be `'static` and cannot
/// borrow from the request. To stream view-encoded data, encode each
/// item inside the stream body and yield
/// [`PreEncoded`](::connectrpc::PreEncoded) — see its `# Streaming
/// example` doc.
#[allow(clippy::type_complexity)]
pub trait SecurityLifecycleService: Send + Sync + 'static {
    /// Handle the ListSecurityLifecycle RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn list_security_lifecycle<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::v1::ListSecurityLifecycleRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::v1::ListSecurityLifecycleResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Handle the ResolveSecurityLifecycleFinding RPC.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn resolve_security_lifecycle_finding<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
}
/// Extension trait for registering a service implementation with a Router.
///
/// This trait is automatically implemented for all types that implement the service trait.
/// Prefer [`Router::add_service`](::connectrpc::Router::add_service) for
/// top-down registration; `register` remains available for compatibility
/// and cases where the service-first call shape is more convenient.
///
/// # Example
///
/// ```rust,ignore
/// use std::sync::Arc;
///
/// let service = Arc::new(MyServiceImpl);
/// let router = service.register(Router::new());
/// ```
pub trait SecurityLifecycleServiceExt: SecurityLifecycleService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: SecurityLifecycleService> SecurityLifecycleServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                SECURITY_LIFECYCLE_SERVICE_SERVICE_NAME,
                "ListSecurityLifecycle",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::v1::ListSecurityLifecycleRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.list_security_lifecycle(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::v1::ListSecurityLifecycleResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(SECURITY_LIFECYCLE_SERVICE_LIST_SECURITY_LIFECYCLE_SPEC)
            .route_view(
                SECURITY_LIFECYCLE_SERVICE_SERVICE_NAME,
                "ResolveSecurityLifecycleFinding",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.resolve_security_lifecycle_finding(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(
                SECURITY_LIFECYCLE_SERVICE_RESOLVE_SECURITY_LIFECYCLE_FINDING_SPEC,
            )
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct SecurityLifecycleServiceRegisterMarker;
impl<
    S: SecurityLifecycleService,
> ::connectrpc::ServiceRegister<SecurityLifecycleServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as SecurityLifecycleServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `SecurityLifecycleService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = SecurityLifecycleServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct SecurityLifecycleServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: SecurityLifecycleService> SecurityLifecycleServiceServer<T> {
    /// Wrap a service implementation in a monomorphic dispatcher.
    pub fn new(service: T) -> Self {
        Self {
            inner: ::std::sync::Arc::new(service),
        }
    }
    /// Wrap an already-`Arc`'d service implementation.
    pub fn from_arc(inner: ::std::sync::Arc<T>) -> Self {
        Self { inner }
    }
}
impl<T> Clone for SecurityLifecycleServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: SecurityLifecycleService> ::connectrpc::Dispatcher
for SecurityLifecycleServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("cerebro.v1.SecurityLifecycleService/")?;
        match method {
            "ListSecurityLifecycle" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            SECURITY_LIFECYCLE_SERVICE_LIST_SECURITY_LIFECYCLE_SPEC,
                        ),
                )
            }
            "ResolveSecurityLifecycleFinding" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(
                            SECURITY_LIFECYCLE_SERVICE_RESOLVE_SECURITY_LIFECYCLE_FINDING_SPEC,
                        ),
                )
            }
            _ => None,
        }
    }
    fn call_unary(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::Payload,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("cerebro.v1.SecurityLifecycleService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "ListSecurityLifecycle" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::v1::ListSecurityLifecycleRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::v1::ListSecurityLifecycleRequest,
                    >::from_parts(&req, &body);
                    svc.list_security_lifecycle(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::v1::ListSecurityLifecycleResponse,
                        >(format)
                })
            }
            "ResolveSecurityLifecycleFinding" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingRequest,
                    >::from_parts(&req, &body);
                    svc.resolve_security_lifecycle_finding(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingResponse,
                        >(format)
                })
            }
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_server_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        request: ::buffa::bytes::Bytes,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("cerebro.v1.SecurityLifecycleService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
    fn call_client_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::UnaryResult {
        let Some(method) = path.strip_prefix("cerebro.v1.SecurityLifecycleService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_unary(path),
        }
    }
    fn call_bidi_streaming(
        &self,
        path: &str,
        ctx: ::connectrpc::RequestContext,
        requests: ::connectrpc::dispatcher::codegen::RequestStream,
        format: ::connectrpc::CodecFormat,
    ) -> ::connectrpc::dispatcher::codegen::StreamingResult {
        let Some(method) = path.strip_prefix("cerebro.v1.SecurityLifecycleService/")
        else {
            return ::connectrpc::dispatcher::codegen::unimplemented_streaming(path);
        };
        let _ = (&ctx, &requests, &format);
        match method {
            _ => ::connectrpc::dispatcher::codegen::unimplemented_streaming(path),
        }
    }
}
/// Client for this service.
///
/// Generic over `T: ClientTransport`. For **gRPC** (HTTP/2), use
/// `Http2Connection` — it has honest `poll_ready` and composes with
/// `tower::balance` for multi-connection load balancing. For **Connect
/// over HTTP/1.1** (or unknown protocol), use `HttpClient`.
///
/// # Example (gRPC / HTTP/2)
///
/// ```rust,ignore
/// use connectrpc::client::{Http2Connection, ClientConfig};
/// use connectrpc::Protocol;
///
/// let uri: http::Uri = "http://localhost:8080".parse()?;
/// let conn = Http2Connection::connect_plaintext(uri.clone()).await?.shared(1024);
/// let config = ClientConfig::new(uri).with_protocol(Protocol::Grpc);
///
/// let client = SecurityLifecycleServiceClient::new(conn, config);
/// let response = client.list_security_lifecycle(request).await?;
/// ```
///
/// # Example (Connect / HTTP/1.1 or ALPN)
///
/// ```rust,ignore
/// use connectrpc::client::{HttpClient, ClientConfig};
///
/// let http = HttpClient::plaintext();  // cleartext http:// only
/// let config = ClientConfig::new("http://localhost:8080".parse()?);
///
/// let client = SecurityLifecycleServiceClient::new(http, config);
/// let response = client.list_security_lifecycle(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.list_security_lifecycle(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.list_security_lifecycle(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct SecurityLifecycleServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> SecurityLifecycleServiceClient<T>
where
    T: ::connectrpc::client::ClientTransport,
    <T::ResponseBody as ::connectrpc::http_body::Body>::Error: ::std::fmt::Display,
{
    /// Create a new client with the given transport and configuration.
    pub fn new(transport: T, config: ::connectrpc::client::ClientConfig) -> Self {
        Self { transport, config }
    }
    /// Get the client configuration.
    pub fn config(&self) -> &::connectrpc::client::ClientConfig {
        &self.config
    }
    /// Get a mutable reference to the client configuration.
    pub fn config_mut(&mut self) -> &mut ::connectrpc::client::ClientConfig {
        &mut self.config
    }
    /// Call the ListSecurityLifecycle RPC. Sends a request to /cerebro.v1.SecurityLifecycleService/ListSecurityLifecycle.
    pub async fn list_security_lifecycle(
        &self,
        request: crate::rpc::proto::cerebro::v1::ListSecurityLifecycleRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.list_security_lifecycle_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ListSecurityLifecycle RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn list_security_lifecycle_with_options(
        &self,
        request: crate::rpc::proto::cerebro::v1::ListSecurityLifecycleRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::v1::__buffa::view::ListSecurityLifecycleResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                SECURITY_LIFECYCLE_SERVICE_SERVICE_NAME,
                "ListSecurityLifecycle",
                request,
                options,
            )
            .await
    }
    /// Call the ResolveSecurityLifecycleFinding RPC. Sends a request to /cerebro.v1.SecurityLifecycleService/ResolveSecurityLifecycleFinding.
    pub async fn resolve_security_lifecycle_finding(
        &self,
        request: crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.resolve_security_lifecycle_finding_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ResolveSecurityLifecycleFinding RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn resolve_security_lifecycle_finding_with_options(
        &self,
        request: crate::rpc::proto::cerebro::v1::ResolveSecurityLifecycleFindingRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::v1::__buffa::view::ResolveSecurityLifecycleFindingResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                SECURITY_LIFECYCLE_SERVICE_SERVICE_NAME,
                "ResolveSecurityLifecycleFinding",
                request,
                options,
            )
            .await
    }
}
