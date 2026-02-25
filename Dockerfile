# syntax=docker/dockerfile:1.7

# Build stage - use buildx cross-compilation (no QEMU needed)
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY api ./api
COPY cmd ./cmd
COPY internal ./internal

# Cross-compile for target platform (fast, no emulation)
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /cerebro ./cmd/cerebro

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget curl

COPY --from=builder /cerebro /usr/local/bin/cerebro
COPY policies /app/policies

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/cerebro"]
CMD ["serve"]
