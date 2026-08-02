.PHONY: all build test test-race vet fmt-check generate reproducible-builds release-gates ard-conformance conformance-typescript local-gates

all: fmt-check vet test build

build:
	GOWORK=off go build ./...

test:
	GOWORK=off go test ./...

test-race:
	GOWORK=off go test -race -count=1 ./...

vet:
	GOWORK=off go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

generate:
	protoc \
		--proto_path=. \
		--go_out=. --go_opt=module=github.com/tosnetwork/tos-protocol \
		--connect-go_out=. --connect-go_opt=module=github.com/tosnetwork/tos-protocol \
		api/tos/edge/v1/worker.proto

reproducible-builds:
	./scripts/verify-reproducible-builds.sh

release-gates:
	./scripts/test-release-bundle.sh

# Networked opt-in gate: fetches and verifies the exact pinned upstream ARD
# commit before running its authoritative tool. It is intentionally separate
# from ordinary offline CI.
ard-conformance:
	./scripts/test-ard-conformance.sh

conformance-typescript:
	node --test sdk/typescript/client.test.mjs

local-gates: fmt-check vet test-race reproducible-builds release-gates conformance-typescript
