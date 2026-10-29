VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X github.com/theo-mazars/best-before/internal/version.Version=$(VERSION)
GOFLAGS := -trimpath

export CGO_ENABLED := 0

.PHONY: all check build test vet fmt-check clean

all: check build

# Same checks as CI; run before every push.
check: fmt-check vet test

fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "Not gofmt-formatted:"; echo "$$unformatted"; exit 1; fi

build:
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/bestbefore-agent ./cmd/bestbefore-agent
	go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/bestbefore ./cmd/bestbefore

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -rf bin dist
