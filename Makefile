GO ?= go
OPA ?= opa
GOLANGCI_LINT ?= golangci-lint

.PHONY: all build check fmt fmt-check lint policy-check policy-test test vet

all: check

build:
	$(GO) build ./...

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	$(GOLANGCI_LINT) run ./...

policy-check:
	$(OPA) check policies

policy-test:
	$(OPA) test -v policies

fmt:
	gofmt -w $$(find . -type f -name '*.go' -not -path './vendor/*')
	$(OPA) fmt -w policies

fmt-check:
	@test -z "$$(gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*'))" || \
		(echo "Go files are not formatted; run 'make fmt'" >&2; exit 1)
	@test -z "$$($(OPA) fmt --diff policies)" || \
		(echo "Rego files are not formatted; run 'make fmt'" >&2; exit 1)

check: fmt-check build vet lint test policy-check policy-test