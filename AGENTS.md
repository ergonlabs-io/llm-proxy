# llm-proxy

High-performance Rust proxy for LLM inference APIs. Speaks standard Envoy
configuration and xDS.

This file is the single agent-instruction file for the repository. It replaced
`CLAUDE.md` in 9c6ec56. Code comments cite its sections by name, for example
`AGENTS.md "Fail-open controls"`. Keep section names stable, or update those
citations when you rename one.

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
6. Values that vary by provider belong on the cluster, never the route. A route
   picks an aggregate, but the member is what gets dialled, so a route-level
   value reaches the wrong provider on failover. Known instances: credentials
   (a key disclosure to a third party), `host_rewrite_literal`, and the
   usage-filter dialect. Cluster headers are applied after route transforms, so
   the selected provider wins on collisions. Assume another instance exists:
   audit anything per-provider that sits on a `RouteEntry`.
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

## Fail-open controls

A security control that fails open must be loud, and the fail-open path needs
its own test. Unset never means open.

- Log loudly rather than fail closed when the owner has chosen availability;
  that makes a bypass visible, not closed. Say which one the code does.
- Warn only where the control was meant to apply. A route with no budget stays
  silent.
- Suppress repeats, or the log becomes the incident. Keep suppression state off
  the healthy hot path.
- Check what the log line renders. Never log a credential; verify hashing in
  the code, not in a comment.

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
reverse dependencies; use `make tq` before landing.

- **Test counts.** Check totals when tests change. A lost `#[tokio::test]`
  turns a test into dead code and the suite stays green. Explain any count
  change before accepting it.
- **Output.** Filter noisy output to reduce noise, never to sample evidence.
  Capture full totals before reasoning from them.
- **Mutation checks.** Scope each mutation to the one test it targets with
  `make t1`, then run the crate once to confirm the restore is clean.
- **Hangs.** `.config/nextest.toml` uses `terminate-after`, so a hung test fails
  instead of stalling. Tests that spawn servers on the test runtime need
  `flavor = "multi_thread"` and requests bounded by `tokio::time::timeout`.
- **Timing.** Do not assert on wall-clock timing windows that a loaded box can
  miss.
- **Measurement.** Prefer per-test or per-binary numbers over aggregates.
  Validate a hand-rolled instrument against a known value before reasoning
  from it. When a fix for the obvious cause makes things worse, revisit the
  diagnosis.
- **Build size.** `[profile.dev] codegen-units = 16` in `Cargo.toml` keeps
  `target/` small on macOS. Do not raise it.

## Coverage

A green suite is not coverage. Ask what the tests never switch on: a suite that
never enables a feature cannot regress it. Verify newly enabled features with an
integration or local-server test (for example `local_openai_smoke.rs`, which is
`#[ignore]`d behind a local Ollama). A tolerant upstream that serves several
protocols can hide a wrong-dialect route; prove a routing hypothesis by changing
only the routing input.

## Running The Product

Worktrees isolate files, not the machine. Ports, `/tmp`, and fixed paths are
global, so an agent that runs the binary is as disruptive as a test suite.

- Use ephemeral ports in tests. Never hardcode a listener port.
- Prefer existing harnesses that spawn and clean up the binary.
- Never run a long-lived process in the foreground. Redirect output, `kill` it,
  and pass `--max-time` to `curl`.
- Check for orphaned listeners with `pgrep` before finishing.
- Before blaming a merge for a new red test, check what else was running.
- In a worktree, `make ci` fails `qa` with `binary not found` because the Go QA
  harness expects `target/debug/llm-proxy`. Set `LLM_PROXY_BIN` or re-run on
  `main`; read the Rust stages directly.

## Delegation

Agent definitions live in `.agents/agents/` and skills in `.agents/skills/`.
`.claude/agents` and `.claude/skills` are symlinks to them so Claude Code still
discovers them; edit the files under `.agents/`. Use the `test-audit` skill
whenever writing, changing, reviewing, or sweeping tests.

- The orchestrator owns architecture, IR shape, Envoy semantics, tricky
  debugging, and final review.
- Use `code-writer` for bounded implementation tasks with explicit files,
  behavior, and validation command.
- Use `test-runner` for verification summaries. It never edits code.
- Give each worker a disjoint file list. Two lanes may share a crate, never a
  file.
- Workers must not run repo-wide writes, `git checkout`, `git restore`, or
  `git stash`. Format only explicit touched files with `rustfmt <paths>`;
  `cargo fmt -p <crate>` is a crate-wide write.
- For concurrent lanes, use separate git worktrees and separate
  `CARGO_TARGET_DIR` values. Resuming an interrupted agent may not restore its
  worktree; check `git status` in the primary tree before writing there.
- Re-run verification after all concurrent edits settle. Treat results gathered
  while another lane writes or runs the product as suspect.
- Commit each verified-green increment before stacking more work. Uncommitted
  work destroyed by a stray `git checkout` is unrecoverable.

## Change Completion

1. Run the narrowest relevant test or check after each substantive edit.
2. Fix local failures before widening scope.
3. Run `make tq-changed` for touched crates.
4. Run `make tq` and `make tq-doc` before landing; run `make ci` when required.
5. Report changed files, validation run, and any unrelated pre-existing failure.
