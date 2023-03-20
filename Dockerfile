# WARNING:
# Not an expert on Docker, use this at your own risk:

FROM cgr.dev/chainguard/go:1.19 as build

WORKDIR /src
COPY go.mod .
RUN go mod download

COPY . .

RUN go get lnproxy
RUN CGO_ENABLED=0 go build -o lnproxy

FROM cgr.dev/chainguard/static:latest

COPY --from=build /src/lnproxy app/lnproxy
CMD ["app/lnproxy"]
