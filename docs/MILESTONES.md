# Milestones — releases, and how a ticket earns its slot

**Updated 2026-07-28.** Companion to `IMPLEMENTATION_PLAN.md` (which owns *what each work
package is*) and the build board (which owns *what state each WP is in*). This document
owns the third axis: **which release a piece of work belongs to, and why.**

The three are deliberately separate. A WP's priority (P0–P3) says what it buys the
product and never changes when the schedule slips. A milestone says when we intend to have
it. Conflating the two is how a P2 quietly becomes "never" — see the plan's "P2 is a
commitment, not a graveyard".

## How to prioritize a ticket

Answer these in order. The first one that discriminates wins.

1. **Does it block the current milestone's ship gate?** If yes, it is the work. Nothing
   below matters.
2. **Is it a correctness or security defect on a path we already serve?** Ship gates do
   not protect broken behavior that is already live. These jump the queue regardless of
   milestone — the `request_headers_to_add` P0 (every request reaching its provider with
   no credentials) and the access-log credential leak both came in this way.
3. **Does it violate a ground rule?** Ground rule #1 (a silently ignored config field) is
   a P0 by definition. These are usually small and always jump ahead of feature work in
   the same milestone.
4. **Otherwise: priority order within the current milestone** — P0, then P1, then P2.
5. **Nothing left in the current milestone?** Pull from the next one. Do not pull P2
   breadth work forward because it is easy; that is how the LLM layer stayed at "two
   files" for as long as it did.

**A ticket that fits no milestone does not get worked.** It gets a P3 and a line in the
plan. That is the point of this document — the backlog is allowed to be large, but the
*active* set has to be small and named.

---

## v0.0.1 — First light ⬅ **current**

**Theme:** one request, all the way through, for real.

A client calls the proxy. The proxy routes it, opens a TLS connection to the upstream
gateway, forwards the request with credentials attached, and returns the response — status,
headers, and body — back to the client intact. Streaming included.

This release carries **everything built to date**. The features are not the milestone; the
working path through them is. A great deal of machinery is finished and green in tests
without ever having carried a real request, and that gap is exactly what this gate closes.

### Ship gate

> A client sends a chat-completion request to the proxy, configured from a single
> `llmproxy` config file pointed at a real provider endpoint, and receives the provider's
> response back unmodified — both non-streaming and streamed (SSE) — for OpenAI and for
> Anthropic.

Verified by the live smoke test in `testing/diffrig`, keys from env. One command, and it
is currently red. That test is `#[ignore]`d today; the gate closes when it runs and passes.

### What's in the release

Shipped and green:

| Area | What works |
|------|-----------|
| **Config** | Envoy bootstrap (YAML/JSON) → typed protos → validated (PGV subset) → IR, with strict mode: every field maps or errors with its dotted path. Plus the `llmproxy` dialect that lowers providers → clusters + TLS + auth headers. |
| **L4** | Listener manager with the 9-step filter-chain matcher, `SO_REUSEPORT` bind/accept, `tcp_proxy` serving real bidirectional streams with half-close and idle timeout. |
| **TLS** | Downstream and upstream, SNI, ALPN, SAN matchers, mTLS, dual-cert hot reload. An upstream `transport_socket` with no registered builder is a fatal startup error, never a silent plaintext downgrade. |
| **HTTP** | h1 downstream; h1 and h2 upstream, dispatched by config. Filter manager implementing S2 (ordering, buffering, local replies, injection, streaming encode). Route table implementing S1 (domain precedence, first-match-wins, weighted pick). |
| **Router** | S9 request transforms (XFF, `x-request-id`, `:authority`, rewrites, `request_headers_to_add`) and S4 timeouts (route, idle, per-try) that disarm on response headers so streams aren't truncated. S3 retry engine with fully-jittered backoff and body replay. S5 `max_requests` circuit breaker. |
| **Clusters** | Cluster manager over `ArcSwap`, STATIC/STRICT_DNS/LOGICAL_DNS discovery, S7 load balancers (round-robin SWRR, random, least-request P2C), active health checking, S6 outlier detection. |
| **Observability** | Access logs with the command-operator format engine, file/stdout/stderr sinks with logrotate reopen, emitted at stream end so streamed responses log real `bytes_sent`. Credentials are snapshotted out before route-injected auth headers are applied. |
| **LLM** | Token extraction for OpenAI chat completions, OpenAI Responses, and Anthropic Messages — streaming and not — into four non-overlapping cost buckets. |
| **Test infra** | Differential rig vs real Envoy v1.38.0 (docker-gated), hermetic TLS e2e with a generated CA, config corpus scorecard, in-process xDS control-plane puppet, open-loop load generator with a capacity model. |

Architecture landed alongside: ADR-0003 (`!Send` worker-local data plane) and ADR-0004
(async filter chain — route resolution owned by the filter manager per S2.8, the router as
a terminal `HttpFilter`, and per-route filter config reaching the IR).

### What's left to close the gate

| WP | P | What it owes |
|----|---|--------------|
| WP-26 | P1 | **The smoke test now exists** (`testing/diffrig/tests/live_smoke.rs`, 4 `#[ignore]`d tests: OpenAI + Anthropic, streaming and not). It has never been *run* — that needs real keys. Running it is what closes this gate. |
| WP-13 | P1 | Whatever the first real provider round-trip exposes; the lifecycle differential suite |
| WP-15 | P1 | Keep-alive reuse — still connect-per-stream, which a real provider will notice |

**The gate is now one command away from an answer**, and nobody has run it:

```sh
OPENAI_API_KEY=... ANTHROPIC_API_KEY=... \
  cargo test -p diffrig --test live_smoke -- --ignored
```

A missing key fails loudly by name rather than skipping — a skipped test
reporting success is exactly how a red gate looks green. The streaming cases
assert time-to-first-frame is well under total duration, which is what
separates real streaming from buffering the whole response and replaying it;
every other assertion passes either way.

Expect this list to grow once the smoke test runs. A path that has never carried a real
request has never been tested, however green the unit suite is — that lesson already cost
us two `StreamInfo` bugs that only a socket-level test found.

### Explicitly not in v0.0.1

Token rate limits, model routing, provider fallback, GenAI metrics (TTFT/TPOT), xDS, the
admin server, and the stats registry. v0.0.1 proves the pipe works. Making the pipe smart
is v0.1.0.

---

## v0.1.0 — LLM gateway

**Theme:** the reason this project exists — be a gateway a team chooses *because* it
understands LLM traffic.

**Ship gate:** the proxy emits per-request token counts (input / cache-read / cache-write /
output) and TTFT/TPOT to the access log for live traffic, enforces a token-based rate
limit, and fails over from one provider to another mid-request without the client seeing an
error.

**In scope:** WP-33 (streaming-first guarantees + GenAI metrics — the encode filter that
finally calls the WP-34 extractor on live traffic), WP-34 remainder (token rate limits;
extraction is done), WP-35 (model routing + provider fallback), **WP-45 (request-body
rewrite pipeline)**, WP-14 hedging.

**WP-33's dialect wiring landed 2026-08-01** (`72c7fc8`, `7e296e3`): the usage filter is in
the `llmproxy` dialect's generated chain with a per-route dialect override, so token counts
reach the access log per provider from one config. QA-1 stopped skipping.

**A hole that wiring exposed, and why WP-45 is now P0 for this gate.** Verified against a
real third-party upstream: without `stream_options.include_usage`, an OpenAI-compatible
provider emits **no usage block in a stream at all**. So the gate's "per-request token
counts for live traffic" is unreachable for any streaming client that doesn't opt in — the
filter works and finds nothing. WP-45 forces the field on. Anthropic is unaffected (it
always reports usage); the gap is exactly OpenAI-dialect + streaming, which is also the
single most common request shape.

**Risk to name out loud:** the dialect currently *rejects* `limits` and `fallbacks` —
correct under strict mode, and precisely the schema pointing at this hole. Those two
features are WP-34 and WP-35. If they slip, v0.1.0 has no content.

---

## v0.2.0 — Production-ready serving

**Theme:** stop claiming "performant" without evidence, and be safe to run unattended.

**Ship gate:** a published capacity report (p99, tokens/sec ceiling, RSS under sustained
long-lived streams) from a run that is not harness-bound, plus `/config_dump` and `/stats`
served by the admin endpoint, plus a config swap under live traffic with zero dropped
streams.

**In scope:** WP-23 (stats registry), WP-25 (admin server), WP-30 (perf — phases 1+2 done,
the ceiling is unpublished), WP-06's swap-under-load gate, IR wiring for WP-18/WP-19
(health checking and outlier detection are both built and green but neither is reachable
from config yet), WP-15 remainder, WP-14 retry budgets.

**Named gaps:**

- The loadgen Linux `/proc` sampler is written to spec but unverified — no Linux box in
  the loop. That is a blocker for this gate, not a footnote.
- `sigterm_drains_then_exits_cleanly` (`crates/proxy/tests/cli.rs`) is **flaky on timing**
  — observed failing once on 2026-07-29, then passing in isolation and on a clean rerun.
  It guards the drain path this milestone's swap-under-load gate depends on, so it has to
  be made deterministic before that gate can mean anything. A test that intermittently
  lies devalues every gate that cites the suite.

---

## v0.3.0 — Dynamic configuration

**Theme:** be deployable the way Envoy is deployed.

**Ship gate:** the proxy takes its entire configuration from an ADS control plane, ACKs and
NACKs correctly per S8, and survives a control-plane reconnect with make-before-break
cluster warming — verified against `testing/controlplane` and a go-control-plane fixture.

**In scope:** WP-20 (ADS SotW), WP-21 (warming/ordering — owns the missing IR `Eds`
discovery variant), WP-22 (SDS + delta xDS; SDS drives WP-08's cert hot-reload seam, which
is built and waiting).

Deferred deliberately: static config carries v0.0.1 through v0.2.0. This is the largest
single block of P2 work and it is genuinely owed — it is the on-ramp that lets a team point
an existing bootstrap at us.

---

## v0.4.0 — Envoy parity

**Theme:** the compatibility moat. Widen the set of configs we accept without a migration.

**Ship gate:** the WP-27 corpus scorecard clears 80% accept on real-world Envoy configs
(baseline 15%), with zero `bug-we-accept` results in the WP-26 differential run.

**In scope:** WP-31/32 (cors, local_ratelimit, then ext_authz/ratelimit/ext_proc),
downstream h2 + upgrades (S10) across WP-10/11/13, the six S1 IR match extensions, WP-29
(fuzzing), WP-40 (dependency-tree cleanup), and the router's known gaps — maintenance mode,
`x-envoy-attempt-count`, redirects (501 today).

The scorecard is the honest instrument: it climbs only when real configs stop being
rejected, and it cannot be gamed by adding tests.

---

## v1.0.0 — Full LLM layer

**Ship gate:** WP-36 (Gateway API Inference Extension / EPP) and WP-37 (realtime WebSocket
sessions, S10) both serving, on top of a green v0.4.0 parity scorecard.

WP-36 needs `ext_proc` from v0.4.0; WP-37 needs S10 upgrade support from v0.4.0. Neither
can move earlier, which is why parity is a v1.0.0 dependency rather than optional breadth.

---

## Milestone hygiene

- **A milestone's scope is frozen when it becomes current.** Work that appears mid-flight
  goes to the next milestone unless it is rule 2 or 3 above (live defect, ground-rule
  violation). Otherwise gates never close.
- **Exit criteria are commands, not adjectives.** If a gate cannot be run, rewrite it.
- **Update this file in the same commit that closes a gate.** A milestone doc that lags the
  code is worse than none — it gets trusted and it is wrong.
- **The board reflects WP status; this file reflects release intent.** When they disagree,
  the board is right about *state* and this file is right about *plan*, and one of them
  needs an edit.
