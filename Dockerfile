# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install git for go mod download
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build controller
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o controller ./cmd/controller

# Build CLI
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o pii-redactor ./cmd/cli

# Runtime stage
FROM alpine:3.23

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /app/controller .
COPY --from=builder /app/pii-redactor /usr/local/bin/

# Create non-root user
RUN addgroup -g 1000 pii && \
    adduser -u 1000 -G pii -s /bin/sh -D pii

USER pii

ENTRYPOINT ["/app/controller"]
