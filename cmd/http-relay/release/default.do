#!/bin/sh -e
os=$(echo $1 | cut -f4 -d-)
arch=$(echo $1 | cut -f5 -d-)
GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -o $3  -a ../main.go
