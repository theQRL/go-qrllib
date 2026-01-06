.PHONY: all test lint check clean

# Use golangci-lint from GOPATH/bin if not in PATH
GOLANGCI_LINT := $(shell which golangci-lint 2>/dev/null || echo "$(HOME)/go/bin/golangci-lint")
GOVULNCHECK := $(shell which govulncheck 2>/dev/null || echo "$(HOME)/go/bin/govulncheck")

# Default target runs all checks
all: check

# Run all checks (lint + test)
check: lint test

# Run linter
lint:
	@echo "Running golangci-lint..."
	@$(GOLANGCI_LINT) run ./...

# Run tests
test:
	@echo "Running tests..."
	@go test ./...

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	@go test -race ./...

# Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	@go test -v ./...

# Install development tools
tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest

# Run vulnerability check
vulncheck:
	@echo "Running govulncheck..."
	@$(GOVULNCHECK) ./...

# Clean test cache
clean:
	@go clean -testcache

# Help
help:
	@echo "Available targets:"
	@echo "  all        - Run all checks (lint + test)"
	@echo "  check      - Run all checks (lint + test)"
	@echo "  lint       - Run golangci-lint"
	@echo "  test       - Run tests"
	@echo "  test-race  - Run tests with race detector"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  tools      - Install development tools"
	@echo "  vulncheck  - Run govulncheck"
	@echo "  clean      - Clean test cache"
