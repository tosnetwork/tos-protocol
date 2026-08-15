#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tools=$(mktemp -d)
trap 'rm -rf "$tools"' EXIT HUP INT TERM

GOBIN="$tools" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
GOBIN="$tools" go install connectrpc.com/connect/cmd/protoc-gen-connect-go@v1.19.1

PATH="$tools:$PATH" protoc -I "$repo/api" \
  --go_out="$repo/gen" --go_opt=paths=source_relative \
  --connect-go_out="$repo/gen" --connect-go_opt=paths=source_relative \
  "$repo/api/tos/service/v1/native.proto"
