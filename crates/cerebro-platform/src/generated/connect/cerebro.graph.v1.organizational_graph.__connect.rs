///Shorthand for `OwnedView<SearchRequestView<'static>>`.
pub type OwnedSearchRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchRequestView<'static>,
>;
///Shorthand for `OwnedView<SearchResponseView<'static>>`.
pub type OwnedSearchResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchResponseView<'static>,
>;
///Shorthand for `OwnedView<GetEntityRequestView<'static>>`.
pub type OwnedGetEntityRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityRequestView<'static>,
>;
///Shorthand for `OwnedView<GetEntityResponseView<'static>>`.
pub type OwnedGetEntityResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityResponseView<'static>,
>;
///Shorthand for `OwnedView<ExpandRequestView<'static>>`.
pub type OwnedExpandRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandRequestView<'static>,
>;
///Shorthand for `OwnedView<ExpandResponseView<'static>>`.
pub type OwnedExpandResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandResponseView<'static>,
>;
///Shorthand for `OwnedView<FindPathsRequestView<'static>>`.
pub type OwnedFindPathsRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsRequestView<'static>,
>;
///Shorthand for `OwnedView<FindPathsResponseView<'static>>`.
pub type OwnedFindPathsResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsResponseView<'static>,
>;
///Shorthand for `OwnedView<ExplainAssertionRequestView<'static>>`.
pub type OwnedExplainAssertionRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<ExplainAssertionResponseView<'static>>`.
pub type OwnedExplainAssertionResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionResponseView<
        'static,
    >,
>;
///Shorthand for `OwnedView<GetSourceSummaryRequestView<'static>>`.
pub type OwnedGetSourceSummaryRequestView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryRequestView<
        'static,
    >,
>;
///Shorthand for `OwnedView<GetSourceSummaryResponseView<'static>>`.
pub type OwnedGetSourceSummaryResponseView = ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryResponseView<
        'static,
    >,
>;
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::SearchResponse>
for crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::SearchResponse>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchResponseView<'static>,
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
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::GetEntityResponse>
for crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::GetEntityResponse>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityResponseView<'static>,
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
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::ExpandResponse>
for crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::ExpandResponse>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandResponseView<'static>,
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
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::FindPathsResponse>
for crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsResponseView<'_> {
    fn encode(
        &self,
        codec: ::connectrpc::CodecFormat,
    ) -> ::std::result::Result<::buffa::bytes::Bytes, ::connectrpc::ConnectError> {
        ::connectrpc::__codegen::encode_view_body(self, codec)
    }
}
impl ::connectrpc::Encodable<crate::rpc::proto::cerebro::graph::v1::FindPathsResponse>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsResponseView<'static>,
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
    crate::rpc::proto::cerebro::graph::v1::ExplainAssertionResponse,
>
for crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionResponseView<
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
    crate::rpc::proto::cerebro::graph::v1::ExplainAssertionResponse,
>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionResponseView<
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
    crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryResponse,
>
for crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryResponseView<
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
    crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryResponse,
>
for ::buffa::view::OwnedView<
    crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryResponseView<
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
pub const ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME: &str = "cerebro.graph.v1.OrganizationalGraphService";
/// Static [`Spec`](::connectrpc::Spec) for the server-side `Search` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const ORGANIZATIONAL_GRAPH_SERVICE_SEARCH_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.graph.v1.OrganizationalGraphService/Search",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `GetEntity` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const ORGANIZATIONAL_GRAPH_SERVICE_GET_ENTITY_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.graph.v1.OrganizationalGraphService/GetEntity",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `Expand` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const ORGANIZATIONAL_GRAPH_SERVICE_EXPAND_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.graph.v1.OrganizationalGraphService/Expand",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `FindPaths` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const ORGANIZATIONAL_GRAPH_SERVICE_FIND_PATHS_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.graph.v1.OrganizationalGraphService/FindPaths",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `ExplainAssertion` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const ORGANIZATIONAL_GRAPH_SERVICE_EXPLAIN_ASSERTION_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.graph.v1.OrganizationalGraphService/ExplainAssertion",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// Static [`Spec`](::connectrpc::Spec) for the server-side `GetSourceSummary` RPC.
///
/// The dispatcher surfaces this on
/// [`RequestContext::spec`](::connectrpc::RequestContext::spec).
pub const ORGANIZATIONAL_GRAPH_SERVICE_GET_SOURCE_SUMMARY_SPEC: ::connectrpc::Spec = ::connectrpc::Spec::server(
        "/cerebro.graph.v1.OrganizationalGraphService/GetSourceSummary",
        ::connectrpc::StreamType::Unary,
    )
    .with_idempotency_level(::connectrpc::IdempotencyLevel::Unknown);
/// OrganizationalGraphService exposes bounded, tenant-scoped graph reads to agents and product clients.
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
pub trait OrganizationalGraphService: Send + Sync + 'static {
    /// Search returns entities matching a label or stable identifier.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn search<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::graph::v1::SearchRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::graph::v1::SearchResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// GetEntity returns one entity by its sealed identifier.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn get_entity<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::graph::v1::GetEntityRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::graph::v1::GetEntityResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// Expand returns the bounded neighborhood around one entity or stable agent key.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn expand<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::graph::v1::ExpandRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::graph::v1::ExpandResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// FindPaths returns bounded directed paths between two entities.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn find_paths<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::graph::v1::FindPathsRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::graph::v1::FindPathsResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// ExplainAssertion returns the stored edge and source runtime for one assertion.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn explain_assertion<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::graph::v1::ExplainAssertionRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::graph::v1::ExplainAssertionResponse,
            > + Send + use<'a, Self>,
        >,
    > + Send;
    /// GetSourceSummary returns the catalog coverage compiled into the running Rust service.
    ///
    /// `'a` lets the response body borrow from `&self` (e.g. server-resident state).
    ///
    /// `request` is borrowed from the request body and is valid for the
    /// duration of the call; message fields are read directly on it
    /// (zero-copy). The response cannot borrow from `request` — use
    /// `.to_owned_message()` (or copy the specific fields) for anything
    /// returned, stored, or moved into `tokio::spawn`.
    fn get_source_summary<'a>(
        &'a self,
        ctx: ::connectrpc::RequestContext,
        request: ::connectrpc::ServiceRequest<
            '_,
            crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryRequest,
        >,
    ) -> impl ::std::future::Future<
        Output = ::connectrpc::ServiceResult<
            impl ::connectrpc::Encodable<
                crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryResponse,
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
pub trait OrganizationalGraphServiceExt: OrganizationalGraphService {
    /// Register this service implementation with a Router.
    ///
    /// Takes ownership of the `Arc<Self>` and returns a new Router with
    /// this service's methods registered.
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router;
}
impl<S: OrganizationalGraphService> OrganizationalGraphServiceExt for S {
    fn register(
        self: ::std::sync::Arc<Self>,
        router: ::connectrpc::Router,
    ) -> ::connectrpc::Router {
        router
            .route_view(
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "Search",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::graph::v1::SearchRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.search(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::graph::v1::SearchResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_SEARCH_SPEC)
            .route_view(
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "GetEntity",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::graph::v1::GetEntityRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.get_entity(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::graph::v1::GetEntityResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_GET_ENTITY_SPEC)
            .route_view(
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "Expand",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::graph::v1::ExpandRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.expand(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::graph::v1::ExpandResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_EXPAND_SPEC)
            .route_view(
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "FindPaths",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::graph::v1::FindPathsRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.find_paths(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::graph::v1::FindPathsResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_FIND_PATHS_SPEC)
            .route_view(
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "ExplainAssertion",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::graph::v1::ExplainAssertionRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.explain_assertion(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::graph::v1::ExplainAssertionResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_EXPLAIN_ASSERTION_SPEC)
            .route_view(
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "GetSourceSummary",
                {
                    let svc = ::std::sync::Arc::clone(&self);
                    ::connectrpc::view_handler_fn(move |
                        ctx,
                        req: ::buffa::view::OwnedView<
                            crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryRequestView<
                                'static,
                            >,
                        >,
                        format|
                    {
                        let svc = ::std::sync::Arc::clone(&svc);
                        async move {
                            let sreq = ::connectrpc::ServiceRequest::<
                                crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryRequest,
                            >::from_parts(req.reborrow(), req.bytes());
                            svc.get_source_summary(ctx, sreq)
                                .await?
                                .encode::<
                                    crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryResponse,
                                >(format)
                        }
                    })
                },
            )
            .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_GET_SOURCE_SUMMARY_SPEC)
    }
}
/// Type-inference marker used by [`Router::add_service`](::connectrpc::Router::add_service).
#[doc(hidden)]
pub struct OrganizationalGraphServiceRegisterMarker;
impl<
    S: OrganizationalGraphService,
> ::connectrpc::ServiceRegister<OrganizationalGraphServiceRegisterMarker>
for ::std::sync::Arc<S> {
    fn register_service(self, router: ::connectrpc::Router) -> ::connectrpc::Router {
        <S as OrganizationalGraphServiceExt>::register(self, router)
    }
}
/// Monomorphic dispatcher for `OrganizationalGraphService`.
///
/// Unlike `.register(Router)` which type-erases each method into an `Arc<dyn ErasedHandler>` stored in a `HashMap`, this struct dispatches via a compile-time `match` on method name: no vtable, no hash lookup.
///
/// # Example
///
/// ```rust,ignore
/// use connectrpc::ConnectRpcService;
///
/// let server = OrganizationalGraphServiceServer::new(MyImpl);
/// let service = ConnectRpcService::new(server);
/// // hand `service` to axum/hyper as a fallback_service
/// ```
pub struct OrganizationalGraphServiceServer<T> {
    inner: ::std::sync::Arc<T>,
}
impl<T: OrganizationalGraphService> OrganizationalGraphServiceServer<T> {
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
impl<T> Clone for OrganizationalGraphServiceServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: ::std::sync::Arc::clone(&self.inner),
        }
    }
}
impl<T: OrganizationalGraphService> ::connectrpc::Dispatcher
for OrganizationalGraphServiceServer<T> {
    #[inline]
    fn lookup(
        &self,
        path: &str,
    ) -> Option<::connectrpc::dispatcher::codegen::MethodDescriptor> {
        let method = path.strip_prefix("cerebro.graph.v1.OrganizationalGraphService/")?;
        match method {
            "Search" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_SEARCH_SPEC),
                )
            }
            "GetEntity" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_GET_ENTITY_SPEC),
                )
            }
            "Expand" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_EXPAND_SPEC),
                )
            }
            "FindPaths" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_FIND_PATHS_SPEC),
                )
            }
            "ExplainAssertion" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_EXPLAIN_ASSERTION_SPEC),
                )
            }
            "GetSourceSummary" => {
                Some(
                    ::connectrpc::dispatcher::codegen::MethodDescriptor::unary(false)
                        .with_spec(ORGANIZATIONAL_GRAPH_SERVICE_GET_SOURCE_SUMMARY_SPEC),
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
        let Some(method) = path
            .strip_prefix("cerebro.graph.v1.OrganizationalGraphService/") else {
            return ::connectrpc::dispatcher::codegen::unimplemented_unary(path);
        };
        let _ = (&ctx, &request, &format);
        match method {
            "Search" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::graph::v1::SearchRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::graph::v1::SearchRequest,
                    >::from_parts(&req, &body);
                    svc.search(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::graph::v1::SearchResponse,
                        >(format)
                })
            }
            "GetEntity" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::graph::v1::GetEntityRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::graph::v1::GetEntityRequest,
                    >::from_parts(&req, &body);
                    svc.get_entity(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::graph::v1::GetEntityResponse,
                        >(format)
                })
            }
            "Expand" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::graph::v1::ExpandRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::graph::v1::ExpandRequest,
                    >::from_parts(&req, &body);
                    svc.expand(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::graph::v1::ExpandResponse,
                        >(format)
                })
            }
            "FindPaths" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::graph::v1::FindPathsRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::graph::v1::FindPathsRequest,
                    >::from_parts(&req, &body);
                    svc.find_paths(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::graph::v1::FindPathsResponse,
                        >(format)
                })
            }
            "ExplainAssertion" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::graph::v1::ExplainAssertionRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::graph::v1::ExplainAssertionRequest,
                    >::from_parts(&req, &body);
                    svc.explain_assertion(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::graph::v1::ExplainAssertionResponse,
                        >(format)
                })
            }
            "GetSourceSummary" => {
                let svc = ::std::sync::Arc::clone(&self.inner);
                Box::pin(async move {
                    let body = ::connectrpc::dispatcher::codegen::request_proto_bytes::<
                        crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryRequest,
                    >(request.encoded()?, format)?;
                    let req: crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryRequestView<
                        '_,
                    > = ::connectrpc::dispatcher::codegen::decode_borrowed_request_view(
                        &body,
                        ctx.decode_options(),
                    )?;
                    let req = ::connectrpc::ServiceRequest::<
                        crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryRequest,
                    >::from_parts(&req, &body);
                    svc.get_source_summary(ctx, req)
                        .await?
                        .encode::<
                            crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryResponse,
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
        let Some(method) = path
            .strip_prefix("cerebro.graph.v1.OrganizationalGraphService/") else {
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
        let Some(method) = path
            .strip_prefix("cerebro.graph.v1.OrganizationalGraphService/") else {
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
        let Some(method) = path
            .strip_prefix("cerebro.graph.v1.OrganizationalGraphService/") else {
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
/// let client = OrganizationalGraphServiceClient::new(conn, config);
/// let response = client.search(request).await?;
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
/// let client = OrganizationalGraphServiceClient::new(http, config);
/// let response = client.search(request).await?;
/// ```
///
/// # Working with the response
///
/// Unary calls return [`UnaryResponse<OwnedView<FooView>>`](::connectrpc::client::UnaryResponse).
/// [`view()`](::connectrpc::client::UnaryResponse::view) borrows the response
/// message, so field access is zero-copy:
///
/// ```rust,ignore
/// let resp = client.search(request).await?;
/// let name: &str = resp.view().name;  // borrow into the response buffer
/// ```
///
/// If you need the owned struct (e.g. to store or pass by value), use
/// [`into_owned()`](::connectrpc::client::UnaryResponse::into_owned):
///
/// ```rust,ignore
/// let owned = client.search(request).await?.into_owned();
/// ```
///
/// [`into_view()`](::connectrpc::client::UnaryResponse::into_view) keeps the
/// zero-copy decoded body (an `OwnedView`) without copying; field access on it
/// goes through `.reborrow()`. Streaming responses yield one
/// [`StreamMessage`](::connectrpc::StreamMessage) per received message from
/// `.message().await` — read fields zero-copy through the generated accessor
/// methods (`msg.name()`) or `.view()`, or convert with `.to_owned_message()`.
#[derive(Clone)]
pub struct OrganizationalGraphServiceClient<T> {
    transport: T,
    config: ::connectrpc::client::ClientConfig,
}
impl<T> OrganizationalGraphServiceClient<T>
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
    /// Call the Search RPC. Sends a request to /cerebro.graph.v1.OrganizationalGraphService/Search.
    pub async fn search(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::SearchRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.search_with_options(request, ::connectrpc::client::CallOptions::default())
            .await
    }
    /// Call the Search RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn search_with_options(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::SearchRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::SearchResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "Search",
                request,
                options,
            )
            .await
    }
    /// Call the GetEntity RPC. Sends a request to /cerebro.graph.v1.OrganizationalGraphService/GetEntity.
    pub async fn get_entity(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::GetEntityRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.get_entity_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the GetEntity RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn get_entity_with_options(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::GetEntityRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetEntityResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "GetEntity",
                request,
                options,
            )
            .await
    }
    /// Call the Expand RPC. Sends a request to /cerebro.graph.v1.OrganizationalGraphService/Expand.
    pub async fn expand(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::ExpandRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.expand_with_options(request, ::connectrpc::client::CallOptions::default())
            .await
    }
    /// Call the Expand RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn expand_with_options(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::ExpandRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExpandResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "Expand",
                request,
                options,
            )
            .await
    }
    /// Call the FindPaths RPC. Sends a request to /cerebro.graph.v1.OrganizationalGraphService/FindPaths.
    pub async fn find_paths(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::FindPathsRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.find_paths_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the FindPaths RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn find_paths_with_options(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::FindPathsRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::FindPathsResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "FindPaths",
                request,
                options,
            )
            .await
    }
    /// Call the ExplainAssertion RPC. Sends a request to /cerebro.graph.v1.OrganizationalGraphService/ExplainAssertion.
    pub async fn explain_assertion(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::ExplainAssertionRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.explain_assertion_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the ExplainAssertion RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn explain_assertion_with_options(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::ExplainAssertionRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::ExplainAssertionResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "ExplainAssertion",
                request,
                options,
            )
            .await
    }
    /// Call the GetSourceSummary RPC. Sends a request to /cerebro.graph.v1.OrganizationalGraphService/GetSourceSummary.
    pub async fn get_source_summary(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryRequest,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        self.get_source_summary_with_options(
                request,
                ::connectrpc::client::CallOptions::default(),
            )
            .await
    }
    /// Call the GetSourceSummary RPC with explicit per-call options. Options override [`ClientConfig`](::connectrpc::client::ClientConfig) defaults.
    pub async fn get_source_summary_with_options(
        &self,
        request: crate::rpc::proto::cerebro::graph::v1::GetSourceSummaryRequest,
        options: ::connectrpc::client::CallOptions,
    ) -> Result<
        ::connectrpc::client::UnaryResponse<
            ::buffa::view::OwnedView<
                crate::rpc::proto::cerebro::graph::v1::__buffa::view::GetSourceSummaryResponseView<
                    'static,
                >,
            >,
        >,
        ::connectrpc::ConnectError,
    > {
        ::connectrpc::client::call_unary(
                &self.transport,
                &self.config,
                ORGANIZATIONAL_GRAPH_SERVICE_SERVICE_NAME,
                "GetSourceSummary",
                request,
                options,
            )
            .await
    }
}
