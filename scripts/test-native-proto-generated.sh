#!/bin/sh
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
snapshot=$(mktemp -d)
trap 'rm -rf "$snapshot"' EXIT HUP INT TERM

mkdir -p "$snapshot/gen/atos/native/v1"
cp "$repo/gen/atos/native/v1/native.pb.go" "$snapshot/gen/atos/native/v1/"
cp "$repo/gen/atos/native/v1/atosnativev1connect/native.connect.go" "$snapshot/gen/atos/native/v1/atosnativev1connect.connect.go"

"$repo/scripts/generate-native-proto.sh"

cmp "$snapshot/gen/atos/native/v1/native.pb.go" "$repo/gen/atos/native/v1/native.pb.go"
cmp "$snapshot/gen/atos/native/v1/atosnativev1connect.connect.go" "$repo/gen/atos/native/v1/atosnativev1connect/native.connect.go"
