# Milestones — releases, and how a ticket earns its slot

**Updated 2026-08-08** (v0.0.1 shipped; current milestone is v0.1.0). Companion to `IMPLEMENTATION_PLAN.md` (which owns *what each work
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

## v0.1.0 — LLM gateway — **SHIPPED 2026-08-08** (tag `v0.1.0`)

> **Ship decision, 2026-08-08.** Tagged on code-complete plus end-to-end verification
> against mock upstreams, **without** the live-provider drill having been run. This is a
> deliberate departure from the standard v0.0.1 set (which shipped on a manual live run,
> executed and recorded), and it is recorded here as a departure rather than folded into the
> gate text, because the next person to read this should not infer a precedent that was never
> established.
>
> The drill exists and is one command:
>
> ```sh
> OPENAI_API_KEY=sk-... cargo test -p diffrig --test live_gate_v0_1_0 -- --ignored
> ```
>
> Three billable calls. It covers the two things mocks cannot: a token budget enforced
> against a **real** provider's usage report, and the credential swap (a real 200 is
> obtainable only if the proxy substituted the provider credential for the client's virtual
> key). **If it is ever run and fails, this section is wrong and the tag is premature** — say
> so here rather than quietly re-tagging.

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

**Update, 2026-08-08: the failover mechanism landed, and the gate's third clause is now
code-complete — that is not the same claim as "v0.1.0 is ready to ship."** Increment 2 landed
across four commits (`cb84f83`, `a2bfef7`, `d4ac161`, `399b954`) on 2026-08-07/08: 2a built the
aggregate-cluster runtime mechanism (`ClusterKind::Aggregate`, member-order failover via
`attempted_clusters`, a host pick that yields its owning member) with a credential-isolation
test that asserts the negative — a request that fails over from provider A to provider B must
**not** carry A's key, not just that B's key is present; 2b-i made it reachable from Envoy-mode
config (`cluster_type` lowering, `LbPolicy::ClusterProvided` as a real IR variant, since Envoy
requires it on an aggregate); 2b-ii added `validate_cluster_graph`, rejecting a missing member,
a nested aggregate, a self-reference, or a duplicate at config time with a dotted path; 2c made
the `llmproxy` dialect lower `fallbacks:` to exactly this, closing the warn-and-drop gap this
document corrected twice (2026-08-03 and again above on 2026-08-06). `examples/llmproxy.yaml`
changed as a direct result — its `gpt-5* → anthropic/claude-sonnet-5` showcase was cross-dialect
and is now correctly rejected at load time; it now falls back to `local-vllm` instead. The one
dependency this WP carried on WP-14 needed no new retry-engine work: 429-as-retriable and
never-retry-after-first-byte were already true by construction, as recorded above.

**Scope actually closes at same-dialect fallback.** Cross-dialect fallback (e.g. `openai`
primary, `anthropic` fallback) is a hard config-time error naming the route and fallback index,
not a silent drop — forwarding an OpenAI-shaped body to Anthropic, or parsing its response with
the wrong dialect's token parser, is the wrong-provider-shape version of WP-48's arithmetic bug.
The request/response translation table this would need is real, unstarted work and has been
split into **WP-52** (scheduled v1.0.0, alongside WP-44, which also extends WP-35). Leaving
WP-35 "open" indefinitely for scope it was never going to finish this milestone would have been
the less honest call than closing it at what actually shipped — **WP-35 is now `done`.**

**All three gate clauses are code-complete. That is still not the same fact as "verified end to
end," and this release stays `current`, not `shipped`, until it is.** QA-1 gives real black-box
evidence for the token-count clause (passing since 2026-08-01). Rate limiting and provider
failover have neither a QA scenario nor a live run against real providers backing them — the
same caveat this document has carried since 2026-08-01, now applying to all three clauses
instead of one. v0.0.1 did not ship on code-complete; it shipped on a live smoke run against
real OpenAI and Anthropic endpoints, run and recorded. Until an equivalent check exists for
rate-limit enforcement and cross-provider failover, this document records the gate's code as
closed and the release as not yet shipped — a judgment call, not a rule the code forces, and
recorded here as one so it can be argued with.

**WP-48 landed the same batch (`41f1c59`), re-scoped by its own audit.** No live overflow bug
existed outside `usage.rs` — everything else already saturated. The real defect: `as_u64()`
returns `None` for a JSON float, so a provider reporting `"output_tokens": 150.0` billed as
zero, silently. Fixed at all five call sites through one helper; unparseable input is now
`None` (renders absent), never `0` (a number someone bills against).

**Update, 2026-08-08 (later the same day): two of the three clauses moved from code-complete
to verified; the third is now the only one that has not.** This is the distinction the
previous update held the release open on, closing for two-thirds of it.

- **Provider failover, verified (`c1314b6`).** `testing/diffrig/tests/failover_e2e.rs` drives
  the real `llm-proxy` binary against a real `llmproxy` dialect config with `fallbacks:` and a
  mock primary forced to 429 — real HTTP over sockets, not the router-unit level
  `router_aggregate.rs` already covered. Three assertions, each mutation-tested: attempt
  accounting exact (one request logged per upstream, catching a proxy that double-dials or
  retries the primary); the credential-isolation negative (the standby receives its own
  `Bearer key-standby`, and `key-primary` appears **nowhere** in what it received — asserted
  as an explicit negative, since a positive-only check passes just as well when both keys are
  on the wire, which is the actual disclosure scenario); and the standby's own Host header
  (mutating WP-35 2c's per-cluster host header turned this red with the primary's host
  arriving at the fallback's endpoint).
- **Token counts + TTFT/TPOT, verified (`b0485e8`) — after fixing a product gap that made it
  impossible.** The `llmproxy` dialect never emitted TPOT: WP-46 built `%LLM_TPOT%`,
  `%LLM_MAX_STALL%`, and `%LLM_RESPONSE_CHUNKS%` on 2026-08-02, but neither dialect log format
  (text or JSON) ever carried them past `%LLM_TTFT%` — a user of the dialect could not obtain
  TPOT at any setting, while this gate names it explicitly. This is a WP-46 **completeness
  gap**, not new scope; both formats now carry all three fields. New QA-10 (`testing/qa/
  SCENARIOS.md`) then proved the values are real, not merely present: against a mock paced at
  400ms TTFT / 150ms inter-chunk, the access log shows `ttft=402ms tpot=122.129ms
  max_stall=152ms`. The load-bearing assertion is TPOT strictly non-zero, because TPOT had
  already shipped one silent bug of exactly that shape (integer-ms division rendering `0` for
  fast providers). Writing that test caught a second, live bug in the same pass:
  `%LLM_RESPONSE_CHUNKS%` over-reported by exactly one on every response with a body —
  `encode_data` timed the synthetic empty end-of-stream frame as a chunk, which also fed a
  phantom gap into `%LLM_MAX_STALL%`. Fixed; TTFT/TPOT themselves were unaffected.
- **Token-based rate limiting remains unverified, and is now the only clause in that state.**
  WP-34's filter enforces 429s from the dialect's `limits` key and is mutation-tested at the
  unit level, but nothing drives the real binary against a real over-limit request the way the
  other two clauses now do. The owner explicitly deferred this verification this session — it
  is the one item left before this release can defensibly flip to `shipped`.

**This release stays `current`, not `shipped`.** v0.0.1 did not ship on code-complete; it
shipped on a live smoke run against real OpenAI and Anthropic endpoints, actually executed and
recorded. Rate-limit enforcement has no equivalent yet — a QA-11-style scenario or a diffrig
drill against the real binary would close it, but nothing has been written or approved for
that as of this update. Holding the release at `current` on one remaining clause, rather than
three, is still this document's judgment call and not something the gate text forces by
itself — recorded here so it can be argued with.

*(Superseded by the ship decision at the top of this section: the drill was written
(`testing/diffrig/tests/live_gate_v0_1_0.rs`) and the release was tagged without running it.)*

### Update, 2026-08-08 (end of day): the third clause is verified — and it was not verifiable at all before today

`testing/diffrig/tests/auth_e2e.rs::two_virtual_keys_on_the_same_tenant_share_one_token_budget`
is the diffrig drill the previous paragraph asked for: the real `llm-proxy` binary, a real
over-limit request, real HTTP over sockets, `429` on exhaustion. Mutation-checked end to end —
reverting the limiter's tenant read makes it return `200` instead of `429`. **All three gate
clauses are now verified.**

**But the more important correction is to what this document said on 2026-08-06**, where the
clause was listed as one of the "two of the three [that] are real", on the grounds that "WP-34's
limiter runs as a filter returning 429 with `x-ratelimit-*`, and the dialect's `limits` key
lowers onto it". Both halves of that were true and the conclusion was still wrong. The limiter
bucketed on `hash_credential(<the client's own `authorization` header>)`, and **nothing verified
that header** — so a caller who exhausted their quota changed one string and received a fresh
one. A limit that any caller can reset on demand is not an enforced limit, and an over-limit
drill written before today would have passed while proving nothing: it would have measured a
single well-behaved client against a bucket that client was free to abandon.

WP-50 increment 2a re-keyed the limiter onto an identity the proxy assigns, which is why the
drill can exist now and could not before. **This is the third time this section has had to walk
back a safety property it asserted from mechanism rather than from a test** (`fallbacks`
warn-and-drop, 2026-08-03; the route-level credential note, 2026-08-06). The recurring error has
one shape: *the component runs* was read as *the property holds*. The two are different claims
and only the second closes a gate clause.

**The residual caveat, stated so it is not discovered later.** All three verifications run
against mock upstreams. v0.0.1 shipped on a live smoke run against real OpenAI and Anthropic
endpoints, and no equivalent live run has been done for this milestone. For failover and rate
limiting the mock is arguably the *better* instrument — forcing a 429 and exhausting a budget on
demand is exactly what a real provider will not do to order — but "arguably better" is an
argument, not the standard v0.0.1 set. Whether v0.1.0 ships on this evidence or waits for a live
smoke is the owner's call, and it is now the **only** thing standing between this release and
`shipped`. The code and its verification are done.

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

**WP-23 progress, 2026-08-08 — and a warning about how to read it.** Increments 1–3 landed
(`ba980f2`, `8764fee`, `d8f6c80`): the registry with per-worker shards, histograms with
Envoy's default buckets, and the Envoy text renderer. `/stats` now returns `200` instead of
the honest 404.

**That is NOT this gate's `/stats` clause being met, and the difference is easy to miss.**
The instrumentation call sites are WP-23 increment 5 and have not landed, so `/stats` today
returns `200` with an **empty body** — a correctly-rendered view of a registry against which
nothing has been recorded. To a Prometheus scraper that is indistinguishable from a healthy
proxy serving no traffic, and it satisfies a naive reading of "`/config_dump` and `/stats`
served by the admin endpoint" while providing nothing at all.

The 404 it replaced carried the comment *"this proxy does not fake an empty /stats"*. That
comment was written to prevent exactly this misreading, so it is restated here rather than
lost with the code that held it: **this clause closes when `/stats` reports real traffic**,
which needs increment 5, and increment 4 (`/stats/prometheus` plus the Grafana-dashboard
conformance test) is what proves the output is Envoy-shaped rather than merely present.

One known unknown to carry into increment 4: **the histogram text line format is
unverified.** Nothing authoritative for it exists in this repo — the vendored protos cover
bucket boundaries, not admin-endpoint rendering — so it sits behind one named function,
labelled as an unconfirmed recollection. The Grafana conformance test is what will settle it.

**Named gaps:**

- The loadgen Linux `/proc` sampler is written to spec but unverified — no Linux box in
  the loop. That is a blocker for this gate, not a footnote.
- ~~`sigterm_drains_then_exits_cleanly` (`crates/proxy/tests/cli.rs`) is **flaky on
  timing**~~ — **closed 2026-08-08, and the diagnosis in this bullet was wrong twice over.**

  The 2026-07-29 timing flake had already been fixed when this bullet was written: the test
  used to gate readiness on a log line emitted *before* the SIGTERM handler was installed,
  and was changed to poll the listener socket instead. It was not "flaky on timing" any
  more. Re-run 12× in isolation on 2026-08-08: 12 passes, 1.14–1.30s, no variance worth the
  name.

  What *was* still wrong is a different bug, and it was not a timing one. The test loaded
  `examples/tcp-proxy.yaml`, which binds a fixed `:10000` (and a fixed admin `:9901`).
  Measured by holding `:10000` from another process: the readiness fence **passed** — it
  connected to the squatter — and the test then failed at the exit-status assertion, three
  screens away, implicating the drain path. A fence that reports ready when a *different*
  process is listening is not a fence; it is a false-negative generator aimed at whatever
  code runs next, which is exactly how a port collision gets written up as "flaky on
  timing".

  Fixed by giving the test its own ephemeral port (the swap its sibling
  `serve_mode_accepts_connections_on_its_listener` already had), verified by re-running with
  both old fixed ports held: 3/3 pass. The general lesson is the one this document keeps
  relearning — "intermittent" is a symptom, and naming it as the cause stops the search
  early.

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
