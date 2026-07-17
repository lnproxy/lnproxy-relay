# Build from the lnproxy-relay repository root:
#
#   docker build -t lnproxy-nostr-relay .
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
ARG TARGETOS=linux
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build -trimpath -ldflags="-s -w" -o /out/nostr-relay ./cmd/nostr-relay

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
	&& adduser -D -u 1000 lnproxy
USER lnproxy
WORKDIR /home/lnproxy
COPY --from=build /out/nostr-relay /usr/local/bin/nostr-relay
EXPOSE 4747
ENTRYPOINT ["nostr-relay"]
