# Multi-stage build for minimal, secure production image

# Stage 1: Build
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Copy dependency files first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY main.go ./

# Build with optimizations
# -ldflags "-s -w" strips debug info for smaller binary
# CGO_ENABLED=0 for static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -extldflags '-static'" \
    -a -installsuffix cgo \
    -o taiji \
    main.go

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12:nonroot

# Copy timezone data and CA certificates from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary from builder
COPY --from=builder /build/taiji /app/taiji

# Use non-root user (distroless nonroot is UID 65532)
USER nonroot:nonroot

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/taiji"]

# Run the service
ENTRYPOINT ["/app/taiji"]
