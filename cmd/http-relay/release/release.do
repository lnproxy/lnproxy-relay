#!/bin/sh -e
hash=`git rev-parse --verify --short HEAD`
redo-ifchange manifest-$hash.txt
echo $hash
