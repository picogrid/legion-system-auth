BINARY_NAME=legion-auth
INSTALL_PATH ?= /usr/local/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildDate=$(BUILD_DATE)"

.PHONY: all build clean test fmt vet lint security check install-service install help

all: build

## build: Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) main.go

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf build/

## test: Run tests
test:
	go test -v -race -coverprofile=coverage.out ./...

## fmt: Format code
fmt:
	go fmt ./...

## vet: Run go vet
vet:
	go vet ./...

## lint: Run golangci-lint
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run --timeout=5m; \
	else \
		echo "golangci-lint not installed. Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
		exit 1; \
	fi

## security: Run security scanner (gosec)
security:
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"; \
		exit 1; \
	fi

## check: Run all checks (fmt, vet, lint, security, test)
check: fmt vet lint security test
	@echo "✓ All checks passed!"

## install: Build and install the binary
install: build
	install -d $(INSTALL_PATH)
	install -m 755 $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)

## install-service: Install as a system service
install-service: build
	./$(BINARY_NAME) install-service

## help: Show this help message
help:
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
