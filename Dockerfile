# syntax=docker/dockerfile:1.7

# Build stage - use buildx cross-compilation (no QEMU needed)
ARG GO_VERSION
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum* ./
RUN --mount=type=cache,id=cerebro-go-mod-cache,target=/go/pkg/mod,sharing=locked \
    go mod download

COPY api ./api
COPY cmd ./cmd
COPY internal ./internal

# Cross-compile for target platform (fast, no emulation)
RUN --mount=type=cache,id=cerebro-go-mod-cache,target=/go/pkg/mod,sharing=locked \
    --mount=type=cache,id=cerebro-go-build-cache,target=/root/.cache/go-build,sharing=locked \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -buildvcs=false -trimpath -ldflags="-s -w" -o /cerebro ./cmd/cerebro

# Runtime image
FROM alpine:3.23

RUN apk add --no-cache curl && addgroup -S cerebro && adduser -S -G cerebro -u 10001 cerebro

COPY --from=builder /cerebro /usr/local/bin/cerebro
COPY policies /app/policies

WORKDIR /app

USER cerebro

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8080/health || exit 1

ENTRYPOINT ["/usr/local/bin/cerebro"]
CMD ["serve"]
