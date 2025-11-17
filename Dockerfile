# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o docktail .

# Runtime stage
FROM alpine:latest

# Install Tailscale from Alpine edge repository (or download static binary)
RUN apk add --no-cache ca-certificates iptables ip6tables && \
    apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community tailscale

WORKDIR /app

# Copy binary from build stage
COPY --from=builder /build/docktail .

ENTRYPOINT ["/bin/sh", "-c", "sleep 1 && exec /app/docktail"]
