FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -o /cerebro ./cmd/cerebro

# Runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates wget

COPY --from=builder /cerebro /usr/local/bin/cerebro
COPY policies /app/policies

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/cerebro"]
