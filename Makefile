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

.PHONY: bench-build
bench-build: ## Build the optimized proxy, mock upstream and loadgen the benchmarks run
	cargo build --release -p proxy -p mockupstream -p loadgen

.PHONY: lab-ab
lab-ab: ## Latency lab A/B on a Linux host: make lab-ab BASE=main CAND=HEAD LAB_HOST=root@IP [PATCH=f]
	scripts/latency-lab.sh ab --base $(or $(BASE),main) --cand $(or $(CAND),HEAD) $(if $(PATCH),--cand-patch $(PATCH))

.PHONY: redb-retention-build
redb-retention-build: ## Build production encrypted redb retention qualification
	cargo build --release -p proxy-capture-spool --example redb_retention

.PHONY: redb-retention-check
redb-retention-check: ## Check production redb qualification reporting without workloads
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_redb_retention.py

.PHONY: install-check
install-check: ## Run scripts/install.sh end to end against the local debug build
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_install.py

.PHONY: helm-check
helm-check: ## helm lint and helm template the chart (deploy/helm/llm-proxy) for each ci/ values file; set LLM_PROXY_BIN to also validate the rendered configs
	testing/helm/check.sh

.PHONY: helm-e2e
helm-e2e: ## Install the chart on a throwaway kind or minikube cluster, send a request, roll it under load (needs docker)
	testing/helm/e2e.sh

.PHONY: check
check: ## Fast type-check of the whole workspace (no codegen)
	cargo check --workspace

.PHONY: test
test: ## Run all tests
	cargo test --workspace

# ------------------------------------------------------------ quiet testing --
# Why these exist: agent context is the scarce resource, and `cargo test`'s
# default output is one line PER PASSING TEST -- ~900 lines of "... ok" that
# say nothing a summary doesn't. `--quiet` prints dots instead, while STILL
# printing the full panic, diff, and backtrace for anything that fails. So the
# detail arrives exactly when it is wanted and never when it isn't.
#
# `--no-fail-fast` matters on the workspace target: plain `--workspace` stops
# at the first failing crate and silently undercounts the total.

# nextest, not `cargo test`, for the workspace targets. Measured 2026-08-07:
# a healthy workspace run is 957 tests in 79s, but runs were routinely hitting
# 656-863s because 8 tests in `diffrig` (mock_e2e, tls_e2e) intermittently HANG
# holding LISTEN sockets, and `cargo test` will wait on them forever with no
# indication of which test is stuck. nextest names slow tests as they pass 60s
# and, via `terminate-after` in .config/nextest.toml, kills them at 3 minutes
# so a hang becomes a NAMED FAILURE instead of an unexplained stall.
#
# nextest does NOT run doctests -- that is a documented gap, not an oversight
# on its part -- so `tq-doc` exists and `ci` runs it explicitly. Skipping it
# would silently stop testing the compiled examples in proxy-simple-config,
# proxy-config/ir.rs, and proxy-filters/usage.rs.

.PHONY: tq
tq: ## Workspace test via nextest (the one agents should use). Excludes doctests; see tq-doc.
	cargo nextest run --workspace

.PHONY: tq-count
tq-count: ## Workspace test, printing ONLY the totals line
	@cargo nextest run --workspace 2>&1 \
	  | grep -E '^\s+Summary' \
	  | sed -E 's/.*Summary[^]]*\] *//'

.PHONY: tq-doc
tq-doc: ## Doctests only -- nextest cannot run these, so they need their own pass
# `--exclude proxy-api` is REQUIRED, not tidiness. proxy-api sets
# `doctest = false` in its Cargo.toml because Envoy's generated proto doc
# comments are full of YAML and protobuf snippets that are not Rust
# (`key: envoy.xxx`, `filter_metadata:`). An explicit `--doc` overrides that
# setting and tries to compile all 33 of them, every one of which fails. The
# normal `cargo test` path respects `doctest = false`, which is why this only
# bites here.
	cargo test --workspace --exclude proxy-api --doc

# The default inner-loop target. Tests ONLY the crates you actually touched,
# instead of paying for the whole workspace on every edit.
#
# Scope, stated plainly so it is not mistaken for a gate: this runs the crates
# whose files changed, and NOT their reverse dependencies. Editing
# `proxy-config/src/ir.rs` will therefore test `proxy-config` and say nothing
# about `proxy-http`, which consumes that IR. That is the deliberate trade --
# it is an inner-loop tool, not a substitute for `make tq` before committing.
#
# BASE selects what "changed" means; it defaults to HEAD (working-tree edits).
# Use `make tq-changed BASE=main` to cover a whole branch.
.PHONY: tq-changed
tq-changed: ## Test only crates you changed, e.g. make tq-changed BASE=main
	@base="$${BASE:-HEAD}"; \
	dirs=$$( { git diff --name-only "$$base" -- crates testing; \
	           git diff --name-only -- crates testing; \
	           git ls-files -o --exclude-standard -- crates testing; } 2>/dev/null \
	         | awk -F/ 'NF>2 {print $$1"/"$$2}' | sort -u ); \
	if [ -z "$$dirs" ]; then echo "tq-changed: nothing changed vs $$base"; exit 0; fi; \
	args=""; \
	for d in $$dirs; do \
	  n=$$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$$d/Cargo.toml" 2>/dev/null | head -1); \
	  if [ -n "$$n" ]; then args="$$args -p $$n"; fi; \
	done; \
	if [ -z "$$args" ]; then echo "tq-changed: no cargo packages resolved from: $$dirs"; exit 0; fi; \
	echo "tq-changed: testing$$args  (vs $$base; reverse deps NOT included)"; \
	cargo nextest run $$args

# Default workspace runs skip these external-store tests.
.PHONY: tq-redis
tq-redis: ## Run Redis store tests (requires LLM_PROXY_TEST_REDIS)
	@test -n "$$LLM_PROXY_TEST_REDIS" || (echo "LLM_PROXY_TEST_REDIS is required"; exit 1)
	cargo nextest run -p proxy-control -p proxy-filters -p proxy --run-ignored all -E 'test(redis)'

# The stable-surface golden files (crates/proxy/tests/golden/). Rewrites them
# from the running code; review and commit the diff as a deliberate change.
.PHONY: golden
golden: ## Regenerate the stable-surface golden files, then review the diff
	UPDATE_GOLDEN=1 cargo nextest run -p proxy -E 'test(/(^|::)golden_/)'

tq-%: ## Test one crate via nextest, e.g. make tq-proxy-http
	cargo nextest run -p $*

# Run ONE test by name, quietly -- what a mutation check should use rather than
# re-running a whole crate. e.g. make t1 CRATE=proxy-filters TEST=hash_credential
.PHONY: t1
t1: ## Run a single test: make t1 CRATE=<crate> TEST=<name substring>
ifndef CRATE
	$(error CRATE is required, e.g. make t1 CRATE=proxy-http TEST=my_test)
endif
ifndef TEST
	$(error TEST is required, e.g. make t1 CRATE=proxy-http TEST=my_test)
endif
	cargo test -p $(CRATE) --quiet $(TEST)

.PHONY: fmt
fmt: ## Format all Rust code (WHOLE REPO -- see fmt-files for the agent-safe one)
	cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting without writing (what CI enforces)
	cargo fmt --all --check

.PHONY: fmt-files
fmt-files: ## Format ONLY the listed files: make fmt-files FILES="a.rs b.rs"
ifndef FILES
	$(error FILES is required, e.g. make fmt-files FILES="crates/proxy-http/src/router.rs")
endif
	rustfmt --edition 2021 $(FILES)

# Why fmt-files exists, and why agents must use it instead of `fmt`:
# `cargo fmt --all` AND `cargo fmt -p <crate>` are both repo/crate-WIDE writes.
# When several agents work concurrently, either one reformats other lanes'
# in-flight uncommitted files. This has caused real losses twice (2026-07-25,
# 2026-07-27) -- see AGENTS.md "Delegation".

.PHONY: lint
lint: ## Clippy with warnings denied (what CI enforces)
	cargo clippy --workspace --all-targets -- -D warnings
	# The optional allocator is off by default, so lint its build too.
	cargo clippy -p proxy --features mimalloc -- -D warnings

.PHONY: ci
ci: ## Everything CI runs: format check, lint, citations, tests (incl. schema gate), doctests, dep audit, config reference, black-box QA
	cargo fmt --all --check
	@$(MAKE) version-check
	@$(MAKE) citations-check
	cargo clippy --workspace --all-targets -- -D warnings
	# The optional allocator is off by default, so lint its build too.
	cargo clippy -p proxy --features mimalloc -- -D warnings
	cargo nextest run --workspace
	@$(MAKE) tq-doc
	@$(MAKE) deps-check
	@$(MAKE) config-reference-check
	@$(MAKE) qa

.PHONY: clean
clean: ## Remove build artifacts
	cargo clean

# Cargo never garbage-collects target/: every profile, feature, flag, or
# toolchain variant leaves another copy of each crate behind. On 2026-10-10
# that reached 105G in target/debug alone (~165 variants of proxy_filters).
# `cargo sweep` deletes artifacts by age and for uninstalled toolchains, and
SWEEP_DAYS ?= 14
.PHONY: clean-stale
clean-stale: ## Delete build artifacts unused for SWEEP_DAYS days (default 14); needs cargo-sweep
	@command -v cargo-sweep >/dev/null || { echo "install with: cargo install cargo-sweep --locked"; exit 1; }
	cargo sweep --time $(SWEEP_DAYS)
	cargo sweep --installed
	@du -sh target

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

# Opt-in, not part of `make ci`: calls real providers over the internet. Each
# test whose credentials are unset prints a `LIVE-SKIP` line and passes, so read
# those lines; LIVE_SMOKE_STRICT=1 turns them into failures. `--no-capture`
# keeps the lines visible and runs the tests one at a time, which also keeps
# free-tier rate limits out of the result. .github/workflows/live-smoke.yml runs
# this weekly. See testing/diffrig/README.md "Live provider smoke tests".
.PHONY: smoke-live
smoke-live: ## Live provider smoke tests (OpenRouter, Vertex, Bedrock, OpenAI, Anthropic); needs keys
	cargo nextest run -p diffrig --test live_smoke --run-ignored ignored-only --no-capture

# Opt-in, not part of `make ci`: downloads the pinned h2spec and starts the binary.
.PHONY: h2spec
h2spec: ## HTTP/2 conformance (h2spec) against the downstream h2 listener, plaintext + TLS
	scripts/h2spec.sh $(ARGS)

# ------------------------------------------------- xDS conformance (docker) --

# The go-control-plane cross-implementation check is an OPT-IN target, NOT part
# of `make ci`. `make ci` stays hermetic and needs no docker.
#
# The risk: an opt-in target has the same shape as `local_openai_smoke.rs`, which
# AGENTS.md "Coverage" records as having quietly stopped running while the suite
# stayed green. A target nobody runs reads as coverage, so run it on a stated
# cadence, not only when someone remembers.

DOCKER := $(shell command -v docker 2>/dev/null)

.PHONY: xds-conformance
xds-conformance: ## Run the xDS client against a real go-control-plane server (needs docker)
ifeq ($(DOCKER),)
	@echo ""
	@echo "=============================================================================="
	@echo " SKIPPING make xds-conformance: no docker found on PATH."
	@echo ""
	@echo " This target checks our ADS client against go-control-plane, the reference"
	@echo " implementation -- the one check that catches us agreeing with ourselves"
	@echo " about the protocol and both being wrong. testing/controlplane's own puppet"
	@echo " server cannot do that: we wrote both sides of it."
	@echo "=============================================================================="
	@echo ""
	@exit 1
else
	# testing/xds-conformance/ builds go-control-plane's own
	# cache/server packages into a real ADS server (Dockerfile pins the exact
	# go-control-plane version -- see its README.md), then runs our real
	# proxy-xds AdsClient against it over a real loopback socket, on an
	# ephemeral host port. See testing/xds-conformance/README.md for what
	# this does and does not check, and its own cadence note.
	cd testing/xds-conformance && cargo test --test go_control_plane -- --ignored --test-threads=1
endif

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
	cd testing/qa && env -u GOROOT go test -count=1 ./...
endif

# `-count=1` is NOT optional. Go's test cache keys on Go inputs and has no idea
# the Rust binary changed underneath it, so a QA run after a Rust change can
# report a cached PASS from the PREVIOUS binary. This bit us on 2026-08-01: a
# deliberate mutation was reported green, and was only caught on a re-run with
# the flag. Same shape as the stale-binary lesson from the auth-header P0.

.PHONY: qa-case
qa-case: ## Run one QA scenario: make qa-case CASE=TestQA1
ifndef CASE
	$(error CASE is required, e.g. make qa-case CASE=TestQA1)
endif
	cargo build --bin llm-proxy
	cd testing/qa && env -u GOROOT go test -count=1 -v -run '$(CASE)' ./scenarios/

.PHONY: qa-list
qa-list: ## List the QA scenario test functions and their case IDs
	@grep -rhoE '^func (Test[A-Za-z0-9_]+)' testing/qa/scenarios/ | sed 's/^func /  /' | sort

.PHONY: qa-fmt
qa-fmt: ## Format the Go QA suite
	cd testing/qa && env -u GOROOT gofmt -w .

.PHONY: qa-vet
qa-vet: ## go vet the Go QA suite
	cd testing/qa && env -u GOROOT go vet ./...

.PHONY: qa-tidy
qa-tidy: ## go mod tidy for the Go QA suite
	cd testing/qa && env -u GOROOT go mod tidy
# `env -u GOROOT` on every Go invocation: the shell profile exports a stale
# GOROOT=/usr/local/go that no longer exists, which makes the toolchain fail in
# confusing ways. Unsetting it per-command fixes it without touching the
# owner's shell environment.

# ------------------------------------------------------------------- protos --

.PHONY: vendor-protos
vendor-protos: ## Re-vendor the pinned Envoy protos (see scripts/vendor-protos.sh)
	./scripts/vendor-protos.sh

# ------------------------------------------------------------ dialect schema --
# schema/llmproxy-v0.schema.json is normative for the --config dialect
# (AGENTS.md "Architecture Invariants", 5). The gate tests run in every
# `cargo nextest run --workspace`; schema-check runs only them.

.PHONY: schema-check
schema-check: ## Validate every example dialect config against the schema; check schema/parser field agreement
	cargo nextest run -p proxy-simple-config --test schema_gate --test schema_parser_agreement

.PHONY: config-reference
config-reference: ## Regenerate the docs-site configuration field reference from the schema
	python3 scripts/gen-config-reference.py

.PHONY: config-reference-check
config-reference-check: ## Fail if the committed configuration field reference is stale
	python3 scripts/gen-config-reference.py --check

# --------------------------------------------------------------- docs site --
# The Astro + Starlight site at docs/site/. `npm install` is not run by these
# targets -- run it once yourself (or let `npm run` fail loudly) so a docs
# edit doesn't pay a dependency-install tax on every invocation.

.PHONY: docs-dev
docs-dev: ## Run the docs site dev server (docs/site), http://localhost:4321
	cd docs/site && npm run dev

.PHONY: docs-build
docs-build: ## Production build of the docs site to docs/site/dist/
	cd docs/site && npm run build

.PHONY: docs-check
docs-check: docs-build ## Build the docs site and fail on a broken internal or repository link
	cd docs/site && npm run check-links

# -------------------------------------------------------------------- deps --

.PHONY: deps-check
deps-check: ## Fail on an unused dependency or an edge against the layering table
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_check_deps.py
	python3 scripts/check-deps.py

.PHONY: version-check
version-check: ## Fail if VERSION differs from the workspace version in Cargo.toml
	@cargo_v=$$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml); \
	file_v=$$(tr -d '[:space:]' < VERSION); \
	if [ "$$cargo_v" != "$$file_v" ]; then \
		echo "VERSION is '$$file_v' but Cargo.toml [workspace.package] version is '$$cargo_v'" >&2; exit 1; \
	fi

.PHONY: citations-check
citations-check: ## Fail if code or user docs cite work packages or planning docs (AGENTS.md "Comments")
	python3 scripts/check-citations.py

.PHONY: deps-list
deps-list: ## Same, but also print the allowlisted suppressions and their reasons
	python3 scripts/check-deps.py --list

# ------------------------------------------------------------------- sweep --
# These start real processes and bind real ports -- never run
# them concurrently with the test suite (AGENTS.md "Running The Product"). The script tears
# down and reports a pgrep check on every exit path, including failure.

.PHONY: sweep
sweep: ## Capacity sweep against the mock upstream: make sweep [ARGS="--upstream-protocol http1"]
	./scripts/capacity-sweep.sh $(ARGS)

.PHONY: sweep-compare
sweep-compare: ## Run the sweep twice, h1 vs h2 upstream, to price connection reuse
	./scripts/capacity-sweep.sh --upstream-protocol http1
	./scripts/capacity-sweep.sh --upstream-protocol http2

.PHONY: bench-added-latency
bench-added-latency: bench-build ## Added p50/p99 latency: direct vs proxy controls off vs on: make bench-added-latency [ARGS="--rounds 5"]
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/added-latency.py $(ARGS)

.PHONY: bench-added-latency-check
bench-added-latency-check: ## Check the added-latency reporter without starting servers
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_added_latency.py

.PHONY: scale-verdict-check
scale-verdict-check: ## Check the scale-run S4/S5 verdicts without starting servers
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p test_scale_verdict.py

.PHONY: sweep-docker
sweep-docker: ## Docker Desktop capacity baseline: proxy pinned to 2 CPUs and 1 GiB
	./scripts/docker-capacity-sweep.sh $(ARGS)

.PHONY: overhead-docker
overhead-docker: ## Docker proxy-vs-direct latency overhead baseline
	./scripts/docker-proxy-overhead.sh $(ARGS)

# --------------------------------------------------------------- admin UI --
# Single-page admin UI (admin-ui/, Vite + React + shadcn-style components).
# The Rust admin server hosts the built output same-origin under /ui when
# LLMPROXY_ADMIN_UI_DIR points at admin-ui/dist/ -- no CORS, no extra port.

.PHONY: ui-install
ui-install: ## Install admin UI dependencies (admin-ui/node_modules)
	cd admin-ui && npm install

.PHONY: ui-build
ui-build: ## Build the admin UI into admin-ui/dist/ for /ui serving
	cd admin-ui && npm run build

.PHONY: ui-test
ui-test: ## Run the admin UI unit tests (vitest)
	cd admin-ui && npm test

.PHONY: ui-dev
ui-dev: ## Run the admin UI dev server on http://localhost:5173 (VITE_ADMIN_URL overrides the API origin)
	cd admin-ui && npm run dev

# ------------------------------------------------------------------- fuzzing --
# cargo-fuzz targets for the hand-written parsers that read client- or
# provider-controlled bytes (fuzz/). fuzz/ is its own workspace, so nothing
# here touches `make tq` or `make ci`. Needs a nightly toolchain and
# `cargo install cargo-fuzz`. FUZZ_TOOLCHAIN picks the nightly; the scheduled
# job (.github/workflows/fuzz.yml) pins a dated one.
#
# Each target runs for FUZZ_SECONDS. A crash leaves its input under
# fuzz/artifacts/<target>/; minimize it with
#   cargo +nightly fuzz tmin <target> <artifact>
# then add the minimized input as a regression test in the owning crate.

FUZZ_TARGETS := usage_extract body_prefix_scan dialect_config model_wildcard vhost_domain \
	route_model_glob access_log_format admin_body virtual_key_auth router_body media_scan \
	multipart_scan
FUZZ_SECONDS ?= 300
FUZZ_TOOLCHAIN ?= nightly

.PHONY: fuzz-build
fuzz-build: ## Build every fuzz target (nightly + cargo-fuzz)
	cargo +$(FUZZ_TOOLCHAIN) fuzz build

.PHONY: fuzz
fuzz: ## Run every fuzz target for FUZZ_SECONDS each (default 300)
	@fuzz/seed.sh
	@for t in $(FUZZ_TARGETS); do \
	  echo "== $$t ($(FUZZ_SECONDS)s)"; \
	  cargo +$(FUZZ_TOOLCHAIN) fuzz run $$t -- -max_total_time=$(FUZZ_SECONDS) || exit 1; \
	done

.PHONY: fuzz-one
fuzz-one: ## Run one fuzz target, e.g. make fuzz-one TARGET=usage_extract FUZZ_SECONDS=600
	@test -n "$(TARGET)" || { echo "set TARGET to one of: $(FUZZ_TARGETS)"; exit 1; }
	@fuzz/seed.sh
	cargo +$(FUZZ_TOOLCHAIN) fuzz run $(TARGET) -- -max_total_time=$(FUZZ_SECONDS)
