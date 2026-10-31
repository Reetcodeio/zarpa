# Zarpa CLI. Run from the repo root.
GO        ?= go
BIN       := bin
PKG       := github.com/Reetcodeio/zarpa
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS   := -s -w -X $(PKG)/internal/version.Version=$(VERSION) \
             -X $(PKG)/internal/version.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo none) \
             -X $(PKG)/internal/version.Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: build install test race lint fmt cross demo clean

build: ## Build the CLI for this machine into bin/zarpa
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/zarpa ./cmd/zarpa

install: build ## Copy the CLI to /usr/local/bin
	install -m 0755 $(BIN)/zarpa /usr/local/bin/zarpa

test: ## Run all tests
	$(GO) test ./...

race: ## Run tests with the race detector
	$(GO) test -race ./...

lint: ## gofmt + go vet (+ golangci-lint when installed)
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run: make fmt" && exit 1)
	$(GO) vet ./...
	@command -v golangci-lint >/dev/null && golangci-lint run || echo "golangci-lint not installed, skipped"

fmt: ## Format the code
	gofmt -w .

cross: ## Build macOS, Linux and Windows binaries into bin/
	for t in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64; do \
	  os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
	    -o $(BIN)/zarpa-$$os-$$arch$$ext ./cmd/zarpa || exit 1; done

demo: build ## Scan a throwaway fake machine full of fake keys (nothing real is touched)
	./scripts/demo.sh

clean:
	rm -rf $(BIN) dist
