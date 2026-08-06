# Milestones — releases, and how a ticket earns its slot

**Updated 2026-08-06** (v0.0.1 shipped; current milestone is v0.1.0). Companion to `IMPLEMENTATION_PLAN.md` (which owns *what each work
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

## v0.0.1 — First light ✅ **shipped 2026-08-01**

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

Verified by the live smoke test in `testing/diffrig`, keys from env. **Run on 2026-08-01
against the real OpenAI and Anthropic endpoints: all four cases passed on the first
attempt. The gate is closed and v0.0.1 is shipped** (tag `v0.0.1`).

The tests remain `#[ignore]`d and always will be — they bill real tokens and CI holds no
keys. So the evidence for this gate is a deliberate manual run, not a CI green, and
re-verifying it is a manual act:

```sh
OPENAI_API_KEY=... ANTHROPIC_API_KEY=... \
  cargo test -p diffrig --test live_smoke -- --ignored
```

**Worth recording honestly: a clean first run is weaker evidence than a run that finds
something.** Four requests exercise one narrow path, and the machinery behind them had
never carried real traffic before. That it worked is good news about the mocks, not proof
the path is robust. This is why coverage stays three-tiered — our mocks, the local Ollama
third-party tier, and real providers — rather than collapsing to "the live test passes".

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

### What closed it, and what did not

| WP | P | Outcome |
|----|---|---------|
| WP-26 | P1 | ✅ **Closed the gate.** `testing/diffrig/tests/live_smoke.rs`, 4 cases (OpenAI + Anthropic, streaming and not), run against real endpoints 2026-08-01, all passing. |
| WP-13 | P1 | The first real round-trip exposed **nothing** — it passed clean. Still open for the lifecycle differential suite, which was never part of this gate. |
| WP-15 | P1 | Still open. Keep-alive reuse — still connect-per-stream. The gate passed without it because four requests cannot surface it; a sustained real workload will. |

A missing key fails loudly by name rather than skipping — a skipped test
reporting success is exactly how a red gate looks green. The streaming cases
assert time-to-first-frame is well under total duration, which is what
separates real streaming from buffering the whole response and replaying it;
every other assertion passes either way. That assertion is the one that makes
the streaming pass mean something.

The expectation going in was that this list would *grow* once the smoke test ran — a path
that has never carried a real request has never been tested, however green the unit suite
is, and that lesson had already cost us two `StreamInfo` bugs that only a socket-level
test found. It did not grow. That is a genuinely good result and also a small one: it says
the mock tier modeled the two providers accurately, not that the path is proven under load,
concurrency, error responses, or long streams. None of those are in the gate.

### Explicitly not in v0.0.1

Token rate limits, model routing, provider fallback, GenAI metrics (TTFT/TPOT), xDS, the
admin server, and the stats registry. v0.0.1 proves the pipe works. Making the pipe smart
is v0.1.0.

---

## v0.1.0 — LLM gateway ⬅ **current**

**Theme:** the reason this project exists — be a gateway a team chooses *because* it
understands LLM traffic.

**Ship gate:** the proxy emits per-request token counts (input / cache-read / cache-write /
output) and TTFT/TPOT to the access log for live traffic, enforces a token-based rate
limit, and fails over from one provider to another mid-request without the client seeing an
error.

**In scope:** WP-33 (streaming-first guarantees + GenAI metrics), WP-34 (token rate limits),
WP-35 (model routing + provider fallback), WP-45 (request-body rewrite pipeline), WP-14
(hedging), and four added since: **WP-46** (TPOT in the access log), **WP-47** (a vendored
Lane-H proto), **WP-48** (the wire-derived-arithmetic sweep), **WP-49** (the provider/model
taxonomy).

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

### Where the gate actually stands (updated 2026-08-06)

Two of the three clauses are real. **Token counts and TTFT/TPOT reach the access log** —
WP-33 wired the usage filter per route, WP-45 forces `stream_options.include_usage` so a
streaming OpenAI client that never opts in still produces usage, and WP-46 added `%LLM_TPOT%`
alongside the existing `%LLM_TTFT%`. **A token-based rate limit is enforced** — WP-34's
limiter runs as a filter returning 429 with `x-ratelimit-*`, and the dialect's `limits` key
lowers onto it.

**Provider failover is the remaining third, and it is the whole risk.** If WP-35 slips, this
gate does not close.

**Correction, 2026-08-03: the dialect does not *reject* `fallbacks`; it warns and serves.**
`lower.rs:527` pushes a `ConfigWarning`, and `crates/proxy/src/main.rs:183` prints warnings to
stderr and proceeds. `parse.rs:180` even resolves each fallback against the provider table
first — so a `fallbacks:` block parses, validates, lowers, and is dropped with one stderr line.
An operator who configures failover gets a proxy that does not fail over. This is deliberate
under the warn-vs-error rule stated at `lower.rs:292` (hard-error only when *every* request
would fail; warn when traffic still serves), and `fallbacks` is one of twelve such sites — but
the earlier wording here claimed a safety property the code does not have, which is how the
`request_headers_to_add` P0 hid for a day. Rejecting is safe; warn-and-drop is not the same
thing and this document should not have said it was.

**A design constraint this exposed, binding on WP-35.** Provider auth is attached at the
*route*: `lower.rs:566` sets `route["request_headers_to_add"]` from the primary provider, and
the IR carries it on `RouteEntry` (`ir.rs:623`). A cross-provider fallback implemented on top
of that would send the primary's API key to the fallback's endpoint. Nothing leaks today —
failover does not happen at all — but WP-35 cannot be built until provider credentials follow
the *cluster* that an attempt actually dialed rather than the route that matched. Envoy's own
precedent for cluster-dependent header mutation is `WeightedCluster.ClusterWeight.
request_headers_to_add`; `envoy.clusters.aggregate` has no equivalent, because aggregate
clusters were designed for failover between homogeneous clusters (same service, different
zones), and LLM providers are the heterogeneous case.

An earlier version of this note said the dialect rejects `limits` **and** `fallbacks`. Neither
is rejected: `limits` was made real by WP-34 increment 3 on 2026-08-02, and `fallbacks` warns
as described above.

**Update, 2026-08-06: the credential-follows-cluster precondition above is now satisfied, not
still binding.** WP-35 increment 1a (`193444e`) added `ClusterConfig.request_headers_to_add`
and made the router apply it to the per-attempt head inside the retry loop; increment 1b
(`b1ca416`) made the `llmproxy` dialect emit provider credentials onto the cluster (via
`Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`) instead of the route — the two
route-level assignments this section described are gone from `lower.rs`. So a cross-provider
fallback built on top of the current shape would **not** leak the primary's key to the
fallback's endpoint. **This does not mean WP-35 is done.** The fallback mechanism itself —
increment 2, an aggregate cluster with member-order failover and a host pick that yields its
owning member — is in progress and, as of this update, uncommitted and unverified. WP-45's
consumer B (body-based model routing), the other named dependency, landed 2026-08-05
(`872b7d7`). The one dependency still open is WP-14's retry/host-repick wiring.

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
from config yet), WP-15 remainder, WP-14 retry budgets, and **WP-51 (OpenTelemetry)**.

**Added 2026-08-03 — WP-51, and a decision that reshapes WP-23.** Owner direction: make the
project OTel-ready, because it is the standard. Recorded and scheduled here rather than worked
now — v0.1.0's scope is frozen and its one open gate clause is still provider failover.

The load-bearing part is not the exporter, it is the **naming decision**: WP-23's registry
carries an **OTel-native internal model** (instruments plus attribute sets, semconv names), and
Envoy's flat dotted names become an adapter rendered for `/stats`. Attributes are strictly more
expressive than flat names — `envoy_cluster_provider:openai_upstream_rq_total` is derivable from
a counter with `{cluster="provider:openai"}`, but the reverse means parsing structure back out
of names we mangled ourselves, and Envoy's label-mangling is lossy. Half the registry is LLM
metrics with no Envoy equivalent anyway, so an Envoy-first model would have invented names for
them regardless.

This does **not** weaken the compatibility moat: Envoy-exact `/stats` output stays a
deliverable, and WP-23's acceptance test (Envoy's own Grafana dashboard queries against our
output) is unchanged and is what keeps the adapter honest.

One state correction worth carrying: `traceparent` already survives a hop today — headers are
cloned per attempt and mutations only add — so we are transparent to existing traces. We simply
do not participate in them. WP-51 is additive, not a defect fix.

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
