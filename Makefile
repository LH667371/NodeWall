APP_NAME := nodewall
GO ?= go
BPF2GO ?= $(GO) run github.com/cilium/ebpf/cmd/bpf2go
GOCACHE ?= $(CURDIR)/.gocache
GOPATH ?= $(CURDIR)/.gopath
GOENV ?= off
CONTAINER_RUNTIME ?=
NODEWALL_BPF_IMAGE ?= nodewall-bpf-gen:go1.27.3
GO_RUN = env GOCACHE=$(GOCACHE) GOPATH=$(GOPATH) GOENV=$(GOENV) $(GO)

.PHONY: generate generate-hostlinux build package package-offline package-update run-agent run-server dev dev-real deploy cleanup test clean help

generate:
	./scripts/gen_bpf.sh

generate-hostlinux:
	$(GO_RUN) generate ./internal/xdp

build:
	$(GO_RUN) build -o bin/nodewall ./cmd/nodewall

package:
	NODEWALL_PACKAGE_FORMAT=binary bash ./scripts/package.sh

package-offline:
	NODEWALL_PACKAGE_FORMAT=archive NODEWALL_PACKAGE_CONTENT=offline bash ./scripts/package.sh

package-update:
	NODEWALL_PACKAGE_FORMAT=archive NODEWALL_PACKAGE_CONTENT=update bash ./scripts/package.sh

run-agent:
	$(GO_RUN) run ./cmd/nodewall agent

run-server:
	$(GO_RUN) run ./cmd/nodewall server

dev:
	NODEWALL_DEV_MODE=demo ./scripts/dev.sh

dev-real:
	NODEWALL_DEV_MODE=real ./scripts/dev.sh

deploy:
	./scripts/deploy.sh

cleanup:
	./scripts/cleanup.sh

set-password:
	./bin/nodewall set-password

test:
	$(GO_RUN) test ./...

clean:
	rm -rf bin
	rm -rf .gocache .gopath
	rm -f bpf/gen/*.o
	rm -f bpf/gen/*_bpf*.go

help:
	@echo "Common commands:"
	@echo "  make build           Build local binary to bin/nodewall"
	@echo "  make package         Build web assets and standalone Linux binaries under dist/"
	@echo "  make package-offline Build archives with the ClamAV engine and offline databases"
	@echo "  make package-update  Build smaller update archives without ClamAV assets"
	@echo "  make package-archive Alias for package-offline (legacy)"
	@echo "  make dev             Run demo mode (UI + server + agent)"
	@echo "  make dev-real        Run real dataplane mode"
	@echo "  make test            Run Go tests"
	@echo "  make clean           Remove build artifacts"
