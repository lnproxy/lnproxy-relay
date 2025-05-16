FROM golang:1-alpine AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o lnproxy ./cmd/http-relay

# Create a minimal runtime image
FROM alpine:3

RUN apk --no-cache add ca-certificates tzdata && \
    adduser -D -h /app lnproxy

WORKDIR /app
USER lnproxy

# Copy the binary from the builder stage
COPY --from=builder --chown=lnproxy:lnproxy /app/lnproxy /app/

# Expose the default port
EXPOSE 4747

# Set the entrypoint
ENTRYPOINT ["/app/lnproxy"]
