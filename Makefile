GO_VERSION := 1.25

.PHONY: build test lint vet check clean setup setup-microvm build-microvm test-microvm \
	build-audit test-audit setup-audit

ARAPUCA_DIR ?= ../arapuca
PREFIX      ?= $(HOME)/.local

build:
	CGO_ENABLED=1 go build ./...

build-microvm:
	CGO_ENABLED=1 go build -tags microvm ./...

test:
	CGO_ENABLED=1 go test -v ./...

test-microvm:
	CGO_ENABLED=1 go test -v -tags microvm ./...

build-audit:
	CGO_ENABLED=1 go build -tags audit ./...

test-audit:
	CGO_ENABLED=1 go test -v -tags audit ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

check: vet test

clean:
	go clean -cache

# Build and install core arapuca (no microvm deps).
setup:
	cd $(ARAPUCA_DIR) && make install PREFIX=$(PREFIX)
	@echo "Done. Run: export PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig"

# Build and install arapuca with micro-VM support (requires libkrun, openssl).
setup-microvm:
	cd $(ARAPUCA_DIR) && make install INSTALL_FEATURES=microvm PREFIX=$(PREFIX)
	@echo "Done. Run: export PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig"
	@echo "Build with: go build -tags microvm ./..."

# Build and install arapuca with the serde feature (audit event JSON).
setup-audit:
	cd $(ARAPUCA_DIR) && make install INSTALL_FEATURES=serde PREFIX=$(PREFIX)
	@echo "Done. Run: export PKG_CONFIG_PATH=$(PREFIX)/lib/pkgconfig"
	@echo "Build with: go build -tags audit ./..."
