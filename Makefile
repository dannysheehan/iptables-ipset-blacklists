GO        ?= go
BINARY    := nft-blocklist
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
BOX       ?= all

.PHONY: all build test lint fmt vet integration e2e e2e-destroy package clean

all: lint test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	$(GO) test ./...

# Refresh golden files after intentional nftgen output changes.
golden:
	$(GO) test ./internal/nftgen -update

fmt:
	gofmt -l -w cmd internal test/e2e/feedserver

vet:
	$(GO) vet ./...

lint: vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed; ran go vet only"; \
	fi

# Real-kernel tests inside an unprivileged user+network namespace: no sudo
# needed, and the host firewall is never touched.
integration: build
	$(GO) build -o bin/feedserver ./test/e2e/feedserver
	test/integration/run.sh

# Full VM matrix. BOX=ubuntu2404|debian12|rocky9|leap156|fedora|all
e2e: build package
	test/e2e/run.sh $(BOX)

e2e-destroy:
	cd test/e2e && vagrant destroy -f

# Build .deb and .rpm with nfpm into dist/. RPM forbids dashes in versions,
# so git-describe suffixes are folded into dots.
PKG_VERSION := $(shell echo $(VERSION) | sed 's/^v//; s/-/./g')

package: build
	@command -v nfpm >/dev/null 2>&1 || { echo "nfpm required: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"; exit 1; }
	mkdir -p dist
	rm -f dist/nft-blocklist_*.deb dist/nft-blocklist-*.rpm
	NFPM_VERSION=$(PKG_VERSION) nfpm package -f packaging/nfpm.yaml -p deb -t dist/
	NFPM_VERSION=$(PKG_VERSION) nfpm package -f packaging/nfpm.yaml -p rpm -t dist/

clean:
	rm -rf bin dist
