.PHONY: all test lint check clean fuzz fuzz-quick test-kat test-fast test-edge test-thread

# Use golangci-lint from GOPATH/bin if not in PATH
GOLANGCI_LINT := $(shell which golangci-lint 2>/dev/null || echo "$(HOME)/go/bin/golangci-lint")
GOVULNCHECK := $(shell which govulncheck 2>/dev/null || echo "$(HOME)/go/bin/govulncheck")

# Fuzz test duration (default: 10s per target)
FUZZ_TIME ?= 10s

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

# Run fast tests only (excludes slow SPHINCS+ tests)
test-fast:
	@echo "Running fast tests (excludes SPHINCS+)..."
	@go test ./crypto/dilithium/... ./crypto/ml_dsa_87/... ./crypto/xmss/... ./wallet/... ./legacywallet/...

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	@go test -race ./...

# Run tests with verbose output
test-verbose:
	@echo "Running tests (verbose)..."
	@go test -v ./...

# Run KAT (Known Answer Test) tests only
test-kat:
	@echo "Running KAT tests..."
	@go test -v ./crypto/ml_dsa_87/... ./crypto/dilithium/... ./crypto/sphincsplus_256s/... -run 'KAT'

# Run KAT tests for fast packages only (excludes SPHINCS+)
test-kat-fast:
	@echo "Running KAT tests (fast packages only)..."
	@go test -v ./crypto/ml_dsa_87/... ./crypto/dilithium/... -run 'KAT'

# Run edge case tests
test-edge:
	@echo "Running edge case tests..."
	@go test -v ./crypto/... -run 'EdgeCase'

# Run edge case tests for fast packages only (excludes SPHINCS+)
test-edge-fast:
	@echo "Running edge case tests (fast packages only)..."
	@go test -v ./crypto/ml_dsa_87/... ./crypto/dilithium/... ./crypto/xmss/... -run 'EdgeCase'

# Run thread safety tests with race detector
test-thread:
	@echo "Running thread safety tests with race detector..."
	@go test -race -v ./crypto/... -run 'ThreadSafety'

# Run thread safety tests for fast packages only (excludes SPHINCS+)
test-thread-fast:
	@echo "Running thread safety tests (fast packages only)..."
	@go test -race -v ./crypto/ml_dsa_87/... ./crypto/dilithium/... ./crypto/xmss/... -run 'ThreadSafety'

# Run all fuzz tests for a short duration
fuzz: fuzz-xmss fuzz-dilithium fuzz-mldsa fuzz-sphincs fuzz-mnemonic
	@echo "All fuzz tests completed."

# Quick fuzz test (shorter duration, essential targets only)
fuzz-quick:
	@echo "Running quick fuzz tests ($(FUZZ_TIME) each)..."
	@go test -fuzz=FuzzXMSSVerify -fuzztime=$(FUZZ_TIME) ./crypto/xmss/...
	@go test -fuzz=FuzzDilithiumVerify -fuzztime=$(FUZZ_TIME) ./crypto/dilithium/...
	@go test -fuzz=FuzzMLDSA87Verify -fuzztime=$(FUZZ_TIME) ./crypto/ml_dsa_87/...
	@go test -fuzz=FuzzMnemonicToBin -fuzztime=$(FUZZ_TIME) ./wallet/misc/...

# Fuzz XMSS signature verification
fuzz-xmss:
	@echo "Fuzzing XMSS ($(FUZZ_TIME))..."
	@go test -fuzz=FuzzXMSSVerify -fuzztime=$(FUZZ_TIME) ./crypto/xmss/...
	@go test -fuzz=FuzzXMSSVerifyWithCustomWOTSParamW -fuzztime=$(FUZZ_TIME) ./crypto/xmss/...

# Fuzz Dilithium signature operations
fuzz-dilithium:
	@echo "Fuzzing Dilithium ($(FUZZ_TIME) per target)..."
	@go test -fuzz=FuzzDilithiumVerify -fuzztime=$(FUZZ_TIME) ./crypto/dilithium/...
	@go test -fuzz=FuzzDilithiumOpen -fuzztime=$(FUZZ_TIME) ./crypto/dilithium/...
	@go test -fuzz=FuzzDilithiumExtractMessage -fuzztime=$(FUZZ_TIME) ./crypto/dilithium/...
	@go test -fuzz=FuzzDilithiumExtractSignature -fuzztime=$(FUZZ_TIME) ./crypto/dilithium/...

# Fuzz ML-DSA-87 signature operations
fuzz-mldsa:
	@echo "Fuzzing ML-DSA-87 ($(FUZZ_TIME) per target)..."
	@go test -fuzz=FuzzMLDSA87Verify -fuzztime=$(FUZZ_TIME) ./crypto/ml_dsa_87/...
	@go test -fuzz=FuzzMLDSA87Open -fuzztime=$(FUZZ_TIME) ./crypto/ml_dsa_87/...
	@go test -fuzz=FuzzMLDSA87ExtractMessage -fuzztime=$(FUZZ_TIME) ./crypto/ml_dsa_87/...
	@go test -fuzz=FuzzMLDSA87ExtractSignature -fuzztime=$(FUZZ_TIME) ./crypto/ml_dsa_87/...

# Fuzz SPHINCS+ signature operations
fuzz-sphincs:
	@echo "Fuzzing SPHINCS+ ($(FUZZ_TIME) per target)..."
	@go test -fuzz=FuzzSphincsPlus256sVerify -fuzztime=$(FUZZ_TIME) ./crypto/sphincsplus_256s/...
	@go test -fuzz=FuzzSphincsPlus256sOpen -fuzztime=$(FUZZ_TIME) ./crypto/sphincsplus_256s/...
	@go test -fuzz=FuzzSphincsPlus256sExtractMessage -fuzztime=$(FUZZ_TIME) ./crypto/sphincsplus_256s/...
	@go test -fuzz=FuzzSphincsPlus256sExtractSignature -fuzztime=$(FUZZ_TIME) ./crypto/sphincsplus_256s/...

# Fuzz mnemonic operations
fuzz-mnemonic:
	@echo "Fuzzing mnemonic operations ($(FUZZ_TIME) per target)..."
	@go test -fuzz=FuzzMnemonicToBin -fuzztime=$(FUZZ_TIME) ./wallet/misc/...
	@go test -fuzz=FuzzBinToMnemonic -fuzztime=$(FUZZ_TIME) ./wallet/misc/...
	@go test -fuzz=FuzzMnemonicRoundTrip -fuzztime=$(FUZZ_TIME) ./wallet/misc/...
	@go test -fuzz=FuzzMnemonicWithValidWords -fuzztime=$(FUZZ_TIME) ./wallet/misc/...

# Install development tools
tools:
	@echo "Installing development tools..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest

# Run vulnerability check
vulncheck:
	@echo "Running govulncheck..."
	@$(GOVULNCHECK) ./...

# Clean test cache and fuzz cache
clean:
	@go clean -testcache -fuzzcache

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Run all checks (lint + test)"
	@echo "  check        - Run all checks (lint + test)"
	@echo "  lint         - Run golangci-lint"
	@echo "  test         - Run all tests"
	@echo "  test-fast    - Run fast tests only (excludes SPHINCS+)"
	@echo "  test-race    - Run tests with race detector"
	@echo "  test-verbose - Run tests with verbose output"
	@echo "  test-kat      - Run KAT tests only"
	@echo "  test-kat-fast - Run KAT tests (fast packages only)"
	@echo "  test-edge     - Run edge case tests"
	@echo "  test-edge-fast- Run edge case tests (fast packages only)"
	@echo "  test-thread   - Run thread safety tests with race detector"
	@echo "  test-thread-fast - Run thread safety tests (fast only)"
	@echo "  fuzz         - Run all fuzz tests (FUZZ_TIME=$(FUZZ_TIME))"
	@echo "  fuzz-quick   - Run essential fuzz tests only"
	@echo "  fuzz-xmss    - Fuzz XMSS signature verification"
	@echo "  fuzz-dilithium - Fuzz Dilithium operations"
	@echo "  fuzz-mldsa   - Fuzz ML-DSA-87 operations"
	@echo "  fuzz-sphincs - Fuzz SPHINCS+ operations"
	@echo "  fuzz-mnemonic- Fuzz mnemonic operations"
	@echo "  tools        - Install development tools"
	@echo "  vulncheck    - Run govulncheck"
	@echo "  clean        - Clean test and fuzz cache"
	@echo ""
	@echo "Fuzz test duration can be customized: make fuzz FUZZ_TIME=30s"
