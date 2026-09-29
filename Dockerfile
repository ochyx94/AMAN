# AMAN - Vulnerability Scanner
# Multi-stage build untuk size optimization

# Stage 1: Builder
FROM golang:1.22-alpine AS builder

# Install C/C++ compiler and SQLite development headers
RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /build

# Copy source
COPY . .

# Build binary (dengan CGO untuk SQLite)
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o aman ./cmd/aman

# Stage 2: Runner
FROM alpine:3.19

LABEL maintainer="AMAN Security Team"
LABEL description="AMAN - Software Vulnerability Scanner"
LABEL version="1.0.0"

# Install CA certificates, SQLite, and curl for healthcheck
RUN apk add --no-cache ca-certificates sqlite-libs curl

# Create non-root user
RUN addgroup -g 1000 aman && \
    adduser -u 1000 -G aman -s /bin/sh -D aman

WORKDIR /opt/aman

# Copy binary dari builder
COPY --from=builder /build/aman .

# Create data directory
RUN mkdir -p /opt/aman/data && chown aman:aman /opt/aman

# Switch to non-root user
USER aman

# Create volume mount point
VOLUME ["/opt/aman/data"]

# Expose port (untuk serve mode)
EXPOSE 8080

# Environment variables
ENV AMAN_HOME=/opt/aman
ENV AMAN_DB=/opt/aman/data/aman.db

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command
ENTRYPOINT ["/opt/aman/aman"]
CMD ["serve", "--port", "8080"]
