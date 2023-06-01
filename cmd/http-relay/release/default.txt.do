#!/bin/sh -e
hash=`git rev-parse --verify --short HEAD`
redo-ifchange \
	lnproxy-http-relay-openbsd-amd64-$hash \
	lnproxy-http-relay-linux-amd64-$hash \
	lnproxy-http-relay-darwin-amd64-$hash

sha256sum \
	lnproxy-http-relay-openbsd-amd64-$hash \
	lnproxy-http-relay-linux-amd64-$hash \
	lnproxy-http-relay-darwin-amd64-$hash
