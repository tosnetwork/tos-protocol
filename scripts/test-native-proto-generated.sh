#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
snapshot=$(mktemp -d)
trap 'rm -rf "$snapshot"' EXIT HUP INT TERM

mkdir -p "$snapshot/gen/tos/service/v1"
cp "$repo/gen/tos/service/v1/native.pb.go" "$snapshot/gen/tos/service/v1/"
cp "$repo/gen/tos/service/v1/tosservicev1connect/native.connect.go" "$snapshot/gen/tos/service/v1/tosservicev1connect.connect.go"

"$repo/scripts/generate-native-proto.sh"

cmp "$snapshot/gen/tos/service/v1/native.pb.go" "$repo/gen/tos/service/v1/native.pb.go"
cmp "$snapshot/gen/tos/service/v1/tosservicev1connect.connect.go" "$repo/gen/tos/service/v1/tosservicev1connect/native.connect.go"
