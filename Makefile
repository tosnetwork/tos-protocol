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
	protoc \
		--proto_path=api \
		--go_out=. --go_opt=module=github.com/tosnetwork/tos-protocol \
		--connect-go_out=. --connect-go_opt=module=github.com/tosnetwork/tos-protocol \
		atos/tos/v1/common.proto \
		atos/tos/v1/identity.proto \
		atos/tos/v1/capability.proto \
		atos/tos/v1/trust.proto \
		atos/tos/v1/settlement.proto \
		atos/tos/v1/proof.proto \
		atos/tos/v1/execution.proto

reproducible-builds:
	./scripts/verify-reproducible-builds.sh

release-gates:
	./scripts/test-release-bundle.sh

ard-conformance:
	./scripts/test-ard-conformance.sh

conformance-typescript:
	node --test sdk/typescript/client.test.mjs

local-gates: fmt-check vet test-race reproducible-builds release-gates conformance-typescript
