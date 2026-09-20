# llm-proxy

High-performance Rust proxy for LLM inference APIs. Speaks standard Envoy
configuration and xDS.

## Communication

- Be concise and direct. Remove filler, pleasantries, and hedging.
- Preserve user's language. Keep technical terms, API names, commands, and exact
  error strings unchanged.
- State findings first. Avoid decorative tables, emojis, and long raw logs.
- Do not invent abbreviations. Keep grammar natural.

## Before Editing

- Read Part 0 of `internal-docs/IMPLEMENTATION_PLAN.md` and the relevant WP.
- Treat S1-S10 appendices as normative Envoy semantics; protos are not the
  source of truth.
- Start from the smallest relevant code path, nearby test, or call site.
- Do not revert or overwrite unrelated user changes.
- Keep edits focused. Do not commit unless explicitly asked.

## Architecture Invariants

1. Strict config mode is default. Every config field must map to IR or fail
   with its full dotted path. Never silently ignore fields.
2. Generated protos stay inside `proxy-config` and `proxy-xds`. Other crates
   consume `crates/proxy-config/src/ir.rs`.
3. `unsafe` is denied workspace-wide.
4. Keep Rust idiomatic. Add a brief `// Rust note:` only for non-obvious
   constructs that help the repository owner learn Rust.
5. `proxy-simple-config` exposes only capabilities already available through
   Envoy mode. `schema/llmproxy-v0.schema.json` is normative for its dialect.
6. Values that vary by provider belong on the cluster, never the route. This
   includes credentials and `host_rewrite_literal`. Cluster headers are applied
   after route transforms, so the selected provider wins on collisions.
7. Reject cross-dialect fallback chains rather than guessing how to parse them.

## Policy Domains

- **Routing:** fleet-scoped aliases, provider order/fallback, upstream model
  IDs, dialect, residency, and rollout. Publish immutable versioned snapshots.
  Users and tenants never select providers.
- **Identity/access:** keys, tenant identity, revocation, tenant model grants,
  and optional user restrictions. Normalize missing tenant to reserved
  `default` at the boundary. Effective models are the intersection of
  `tenant_allowed` and `user_allowed`; user restrictions only narrow access.
  Revocation must not wait for routing rollout.
- **Spend:** tenant and optional user budgets plus operational counters. Enforce
  both scopes when both are configured.

Keep `routing_revision`, `policy_generation`, and counter reconciliation
separate. Request workers never query disk or remote stores.

Every completed request emits usage containing tenant, user, requested model,
selected provider/model, rate-card version, token usage, cost, status, and
latency. Scope user queries to that user. Do not put raw unbounded `user_id`
values in Prometheus-style labels. Charge the provider cluster actually dialled,
including its rate card, after fallback.

## Build And Test

Use `make` targets, not bare `cargo test`:

```text
make help                 # list targets
make tq-changed           # changed crates; default edit loop
make tq-<crate>           # one crate
make tq                   # full workspace before landing
make tq-doc               # doctests; nextest does not run them
make ci                   # fmt, clippy, tests, doctests, and QA
make tq-count             # test totals
make t1 CRATE=x TEST=y    # one mutation target
make validate             # load examples/tcp-proxy.yaml
```

`cargo` and `protoc` are expected on `PATH`. `make tq-changed` does not test
reverse dependencies; use `make tq` before landing. Check test counts when
tests change. A green suite is not coverage: verify newly enabled features with
an appropriate integration or local-server test.

For concurrent lanes, use separate git worktrees and separate
`CARGO_TARGET_DIR` values. Assign disjoint file lists. Worktrees do not isolate
ports, `/tmp`, or other machine-global resources. Never run a long-lived server
in the foreground; prefer existing harnesses, bound requests with timeouts,
clean up processes, and check for orphaned listeners.

## Delegation

- The orchestrator owns architecture, IR shape, Envoy semantics, tricky
  debugging, and final review.
- Use `code-writer` for bounded implementation tasks with explicit files,
  behavior, and validation command.
- Use `test-runner` for verification summaries. It never edits code.
- Give each worker a disjoint file list. Workers must not run repo-wide writes,
  `git checkout`, `git restore`, or `git stash`.
- Format only explicit touched files with `rustfmt`; do not run a repo-wide
  formatter from a delegated lane.
- Re-run verification after all concurrent edits settle. Treat results gathered
  while another lane writes or runs the product as suspect.
- Commit each verified-green increment before stacking more work when operating
  a multi-lane batch.

## Change Completion

1. Run the narrowest relevant test or check after each substantive edit.
2. Fix local failures before widening scope.
3. Run `make tq-changed` for touched crates.
4. Run `make tq` and `make tq-doc` before landing; run `make ci` when required.
5. Report changed files, validation run, and any unrelated pre-existing failure.
