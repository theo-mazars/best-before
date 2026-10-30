VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X github.com/theo-mazars/best-before/internal/version.Version=$(VERSION)
GOFLAGS := -trimpath

.PHONY: all check build check-pins update-pins test vet fmt-check clean

all: check build

# Same checks as CI; run before every push.
check: fmt-check vet test

fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "Not gofmt-formatted:"; echo "$$unformatted"; exit 1; fi

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/bestbefore-agent ./cmd/bestbefore-agent
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/bestbefore ./cmd/bestbefore

# Reports container images pinned by digest whose tag has a newer build.
check-pins:
	./scripts/check-pins.sh

update-pins:
	./scripts/check-pins.sh --update

test:
	go test -race ./...

vet:
	go vet ./...

clean:
	rm -rf bin dist
