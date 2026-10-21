.PHONY: build vet lint test readme smoke smoke-quick clean

GOFLAGS ?= -trimpath

# build compiles every package in the module. It is the fastest "did I break
# anything" check.
build:
	go build $(GOFLAGS) ./...

# vet runs `go vet` against every package on every OS the library targets.
# Cross-vet catches mistakes in OS-tagged backends without a real CI runner.
vet:
	GOOS=darwin go vet ./...
	GOOS=windows go vet ./...

# lint runs golangci-lint against both OS trees, as CI does.
lint:
	GOOS=darwin golangci-lint run ./...
	GOOS=windows golangci-lint run ./...

# test runs unit tests with the race detector. Live DNS checks use make smoke.
test:
	go test $(GOFLAGS) -race ./...

# readme checks that the README's split-DNS excerpt matches example_test.go.
readme:
	./scripts/check-readme-go.sh README.md

# WARNING: smoke and smoke-quick change THIS machine's DNS configuration.
# Run them on a disposable host or CI runner.

# smoke runs the host OS's full smoke matrix.
smoke: build
	go run $(GOFLAGS) ./internal/cmd/smoketest

# smoke-quick runs the macOS catch-all + split pair, the short feedback loop
# on a darwin dev host. The harness picks its matrix from the host OS, so
# M-prefixed rows fail elsewhere.
smoke-quick: build
	go run $(GOFLAGS) ./internal/cmd/smoketest -rows M1,M2

# clean removes build artifacts.
clean:
	rm -rf bin/
