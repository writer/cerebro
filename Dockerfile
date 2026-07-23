# syntax=docker/dockerfile:1.7

# Build stage - use buildx cross-compilation (no QEMU needed)
ARG GO_VERSION=1.26.5
ARG RUST_VERSION=1.93.1
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG GO_BUILD_PARALLELISM=2

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum* ./
COPY internal/eventregistry/go.mod ./internal/eventregistry/go.mod
RUN --mount=type=cache,id=cerebro-go-mod-cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY api ./api
COPY cmd ./cmd
COPY gen ./gen
COPY internal ./internal
COPY sources ./sources

# Cross-compile for target platform (fast, no emulation)
RUN --mount=type=cache,id=cerebro-go-mod-cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=cerebro-go-build-cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -p=${GO_BUILD_PARALLELISM} -buildvcs=false -trimpath -ldflags="-s -w" -o /cerebro ./cmd/cerebro

FROM --platform=$TARGETPLATFORM rust:${RUST_VERSION}-alpine AS rust-builder

WORKDIR /app

RUN apk add --no-cache build-base musl-dev openssl-dev openssl-libs-static pkgconfig

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY internal ./internal
COPY tools ./tools

RUN --mount=type=cache,id=cerebro-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cerebro-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo build --locked --release \
      -p cerebro-sourceruntime-eventadmission --bin cerebro-event-admission-worker \
      -p cerebro-platform --bin cerebro-platform

FROM alpine:3.24 AS organizational-catalog
COPY internal/connectorcatalog/catalog /app/internal/connectorcatalog/catalog
COPY sources /app/sources
RUN find /app/sources -mindepth 2 -type f ! -name catalog.yaml -delete

# Runtime image
FROM alpine:3.24

RUN apk upgrade --no-cache && \
    apk add --no-cache curl && \
    addgroup -S cerebro && \
    adduser -S -G cerebro -u 10001 cerebro

COPY --from=builder --chmod=0755 /cerebro /usr/local/bin/cerebro
COPY --from=rust-builder --chmod=0755 /app/target/release/cerebro-event-admission-worker /usr/local/bin/cerebro-event-admission-worker
COPY --from=rust-builder --chmod=0755 /app/target/release/cerebro-platform /usr/local/bin/cerebro-platform
COPY --from=organizational-catalog --chown=10001:101 /app/internal/connectorcatalog/catalog /app/internal/connectorcatalog/catalog
COPY --from=organizational-catalog --chown=10001:101 /app/sources /app/sources
COPY policies /app/policies

WORKDIR /app

USER cerebro

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/livez || exit 1

ENTRYPOINT ["/usr/local/bin/cerebro"]
CMD ["serve"]
