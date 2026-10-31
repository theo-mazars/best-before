VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X github.com/theo-mazars/best-before/internal/version.Version=$(VERSION)
GOFLAGS := -trimpath

.PHONY: all check build build-linux build-agent-linux image dry-run check-pins update-pins test vet fmt-check clean

all: check build

# Same checks as CI; run before every push.
check: fmt-check vet test

fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "Not gofmt-formatted:"; echo "$$unformatted"; exit 1; fi

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/bestbefore-agent ./cmd/bestbefore-agent
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/bestbefore ./cmd/bestbefore

# Cross-compiles the agent for Linux, e.g. to try it from macOS.
LINUX_ARCH ?= $(shell go env GOARCH)
build-agent-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(LINUX_ARCH) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/linux-$(LINUX_ARCH)/bestbefore-agent ./cmd/bestbefore-agent

build-linux: build-agent-linux
	CGO_ENABLED=0 GOOS=linux GOARCH=$(LINUX_ARCH) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/linux-$(LINUX_ARCH)/bestbefore ./cmd/bestbefore

# The dashboard image, built from source inside Docker.
image:
	docker build -f packaging/docker/Dockerfile --build-arg VERSION=$(VERSION) -t bestbefore:$(VERSION) .
	@echo "Built bestbefore:$(VERSION)"

# Runs the agent's dry run here, or in a container if this machine has no APT.
# See scripts/dry-run.sh for running it on a server over SSH.
dry-run:
	./scripts/dry-run.sh

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
