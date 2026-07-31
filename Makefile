.PHONY: all build test test-race vet fmt-check generate

all: fmt-check vet test build

build:
	go build ./...

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

generate:
	protoc \
		--proto_path=. \
		--go_out=. --go_opt=module=github.com/tosnetwork/tos-protocol \
		--connect-go_out=. --connect-go_opt=module=github.com/tosnetwork/tos-protocol \
		api/tos/edge/v1/worker.proto
