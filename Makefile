# llm-proxy developer entry points.
#
#   make help              list all targets
#   make build             debug build of the whole workspace
#   make check-proxy-http  check a single crate (pattern works for any crate)
#
# Per-crate pattern targets accept any package name from the workspace:
#   proxy-api proxy-config proxy-core proxy-http proxy-cluster proxy-xds
#   proxy-observability proxy-admin proxy-filters proxy-simple-config proxy
#   diffrig corpus controlplane

CONFIG ?= examples/tcp-proxy.yaml

.DEFAULT_GOAL := help

# ---------------------------------------------------------------- workspace --

.PHONY: help
help: ## List available targets
	@grep -E '^[a-zA-Z_%-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[1m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Debug build of every crate + the llm-proxy binary
	cargo build --workspace

.PHONY: release
release: ## Optimized build of the llm-proxy binary (target/release/llm-proxy)
	cargo build --release -p proxy

.PHONY: check
check: ## Fast type-check of the whole workspace (no codegen)
	cargo check --workspace

.PHONY: test
test: ## Run all tests
	cargo test --workspace

.PHONY: fmt
fmt: ## Format all code
	cargo fmt --all

.PHONY: lint
lint: ## Clippy with warnings denied (what CI enforces)
	cargo clippy --workspace --all-targets -- -D warnings

.PHONY: ci
ci: ## Everything CI runs: format check, lint, tests, black-box QA
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	@$(MAKE) qa

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean

# ----------------------------------------------------------------- per crate --

check-%: ## Check one crate, e.g. make check-proxy-config
	cargo check -p $*

build-%: ## Build one crate, e.g. make build-proxy-api
	cargo build -p $*

test-%: ## Test one crate, e.g. make test-proxy-config
	cargo test -p $*

# -------------------------------------------------------------------- binary --

.PHONY: run
run: ## Run the proxy with CONFIG (default: examples/tcp-proxy.yaml)
	cargo run -p proxy -- -c $(CONFIG)

.PHONY: validate
validate: ## Validate CONFIG and exit, e.g. make validate CONFIG=my-bootstrap.yaml
	cargo run -p proxy -- -c $(CONFIG) --mode validate

# --------------------------------------------------------------- QA (Go) --

# Evaluated at parse time (not recipe time), so `ifeq` below can branch on it
# without invoking `go` itself — this check only needs to know a `go`
# binary exists on PATH, not run it, so a stale GOROOT can't break it.
GO := $(shell command -v go 2>/dev/null)

.PHONY: qa
qa: ## Build the proxy binary + run the black-box QA suite (testing/qa, Go)
ifeq ($(GO),)
	@echo ""
	@echo "=============================================================================="
	@echo " SKIPPING make qa: no Go toolchain found on PATH (command -v go found nothing)."
	@echo " Install Go (e.g. \`brew install go\`) to run the black-box QA suite."
	@echo " See testing/qa/SCENARIOS.md for what this suite covers."
	@echo "=============================================================================="
	@echo ""
else
	cargo build --bin llm-proxy
	cd testing/qa && env -u GOROOT go test ./...
endif

# ------------------------------------------------------------------- protos --

.PHONY: vendor-protos
vendor-protos: ## Re-vendor the pinned Envoy protos (see scripts/vendor-protos.sh)
	./scripts/vendor-protos.sh

# ------------------------------------------------------------------- boards --
# Tracking artifacts are GENERATED. Edit docs/boards/*.yaml, never the HTML --
# the HTML is overwritten by `make boards` and any hand edit is lost.

.PHONY: boards
boards: ## Render the build board + release tracker from docs/boards/*.yaml
	python3 scripts/render-boards.py

.PHONY: boards-check
boards-check: ## Fail if the rendered HTML has drifted from the YAML
	python3 scripts/render-boards.py --check
