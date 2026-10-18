# QA scenarios — the registry

**Suite:** `testing/qa/` (Go). This document is the **spec the suite is written
from**, and it is tracked in git (via an explicit `.gitignore` exception) so it
can be reviewed alongside the tests that cite its case IDs.

## Status

| Case  | Property                                                   | State                                                   |
| ----- | ---------------------------------------------------------- | ------------------------------------------------------- |
| QA-1  | Per-route token counts, both providers, one config         | passing — fully, including tokens, since 2026-08-01     |
| QA-2  | Bad config fails loudly with the field path, exits nonzero | passing                                                 |
| QA-3  | Streamed response arrives incrementally                    | passing                                                 |
| QA-4  | Credentials reach upstream, never reach the log            | passing                                                 |
| QA-5  | Non-streaming responses log real bytes and tokens          | approved                                                |
| QA-6  | Upstream dying mid-stream errors, and is not retried       | passing                                                 |
| QA-7  | SIGTERM during an active stream drains to completion       | passing                                                 |
| QA-8  | Circuit-breaker rejection fails fast, does not queue       | approved                                                |
| QA-10 | TTFT and TPOT reach the access log with sane values        | passing — since 2026-08-08 (`qa10_llm_latency_test.go`) |
| QA-11 | Redis tenant-to-key cutover and persisted spend after SIGKILL | passing — requires `QA_REDIS_ADDR` |
| QA-12 | Three-process Redis partition, checkpointed SIGKILL, and recovery | passing — requires `QA_REDIS_ADDR` |
| QA-13 | Billing ledger: SIGKILL durability, redelivery, disk cap in both modes | passing — since 2026-10-17 (`qa13_billing_ledger_test.go`); approved through the billing-ledger backlog acceptance (owner, 2026-10-17) |
| QA-14 | Trace export captures an opted-in tenant only, reassembled | passing — since 2026-10-17 (`qa14_trace_export_test.go`); approved through the trace-export backlog acceptance (owner, 2026-10-17) |
| QA-9  | ~~Content-type parameter tolerance~~                       | rejected — see below                                    |

States: `proposed` → `approved` → `implemented` → `passing`. Nothing skips
`approved`.

### QA-1 found two independent gaps — both now fixed

On its very first run, QA-1 established that both providers receive exactly one
request each (routing and provider dispatch work end to end), and then **the
configured access-log file was never created at all**. Two separate things were
in the way:

1. ~~**The `llmproxy` dialect never wires `observability.access_logs` into the
   generated Envoy config.**~~ **FIXED** — commit _"Emit access logs from the
   llmproxy dialect"_. `crates/proxy-simple-config/src/lower.rs` used to emit
   only a warning (_"access logging is recorded but not emitted yet"_)
   and never add an `access_log` entry to the HCM. That warning was **stale**:
   Access logging had landed and worked fully in Envoy mode; only the
   dialect lowering was missing, so a proxy configured the way users actually
   configure it produced **no access logs whatsoever**.
2. ~~**The usage filter isn't in the dialect's generated
   `http_filters`**, so every `%LLM_*_TOKENS%` operator renders as the
   absent-value `-`.~~ **FIXED 2026-08-01** — commits _"Teach the usage filter
   to read a per-route dialect"_ (`7e296e3`) and _"Emit the usage filter from
   the llmproxy dialect, per route"_ (`72c7fc8`). The filter now sits ahead of
   the router in the dialect's chain, and each route carries a
   `typed_per_filter_config` override naming its own provider's dialect — which
   is what lets one proxy meter OpenAI and Anthropic correctly from one config.

Gap 1 was not anticipated by the code review that produced the usage-filter brief —
an independently written black-box test found it from the outside. That is the
argument for this suite existing, and it arrived on day one.

**QA-1's current shape.** Rather than being all-or-nothing on the token counts,
it asserts everything that did not depend on the usage filter — two log lines, one per
route, correct `path`, `response_code` 200, `bytes_sent` > 0 — and degraded to
a loud `t.Skip` naming the usage filter only for the token assertions. The access-log file
failing to appear is a hard failure, since that is a regression of the fix
above.

**It tightened automatically when the usage filter landed**, which was the point of
building it that way: no edit was needed on 2026-08-01: the skip simply stopped
firing and the case began asserting `111/222` on the OpenAI route and `444/555`
on the Anthropic one. Keep the degrade-to-skip shape for future cases blocked
on unshipped work — a case that cannot run yet is still worth writing, provided
it says loudly why and starts asserting on its own.

> **Run QA with `-count=1`.** Go's test cache keys on Go inputs and has no idea
> the Rust binary changed underneath it. A QA run after a Rust change can report
> a cached PASS from the previous binary — this actually happened on 2026-08-01
> during a mutation check, and the mutation was only caught after re-running
> with `-count=1`. This is the same shape as the stale-binary lesson from the
> auth-header P0.

A note for anyone writing assertions against a `json_format` line: **every
value is a JSON string**, including numeric ones (`"response_code":"200"`), and
an absent value is the literal `"-"`. Envoy's `json_format` values are
command-operator format strings, so this matches it. Parse, don't type-assert.

### Third finding, now fixed: pseudo-header operators always rendered `-`

Visible in QA-1's captured lines as `method:-` and `authority:-`.
`header_lookup` resolved a `%REQ(x)%` operator against an `http::HeaderMap`,
and `http::HeaderName` cannot hold a leading colon — so no pseudo-header name
could ever match. Only `:PATH` appeared to work, via a workaround that
injected `x-envoy-original-path` into the logged snapshot.

This mattered well beyond the dialect: **Envoy's own default access-log format
uses `%REQ(:METHOD)%`**, so every access log the proxy wrote in Envoy mode was
missing the request method too. Fixed in _"Resolve Envoy pseudo-headers in
access-log REQ/RESP operators"_ — `LogContext` now carries the pseudo-headers
as typed fields, `%RESP(:STATUS)%` works, and the unfaithful
`x-envoy-original-path` injection is gone.

Worth noting how this one hid: `header_lookup`'s own doc comment _described_
the behavior as intended ("those simply never match today"), so two passes of
code review read it as a known limitation rather than a live defect. The
black-box test had no such prior and just saw a missing method.

**Still open:** `:scheme` renders `-` for origin-form HTTP/1 requests, because
it is derived from the request URI alone. Deriving it from the listener's TLS
state needs downstream connection info that is not threaded that far yet.
Deliberate and documented, not silently wrong — a candidate case if the owner
wants it covered.

### QA-6 found a fourth gap, now fixed: no `response_flags` for a mid-stream body error

On its first run, QA-6 established the two load-bearing properties cleanly:
the mock's request counter stays at exactly 1 (no retry fires once the first
response byte has reached the client, per S3), and the client's read of the
proxied stream reliably ends in an observable error (`unexpected EOF`), never
a clean close indistinguishable from success. The third property — that the
access log's `response_flags` field records the failure — did **not** hold.

Every `set_response_flag` call site in `proxy-http` (all twelve of them, in
`crates/proxy-http/src/router.rs`) is in the PRE-response-headers path:
connect failure, TLS handshake failure, reset-before-headers, request
timeout, codec error before headers. Once headers (and, for a stream, the
first body frames) had already reached the client, nothing set a
`ResponseFlag` when the response _body_ subsequently errored —
`LoggingBody::poll_frame` discarded the error outright (`Err(_)`), so the line
rendered `response_flags` as the absent-value `-` even though the request had
definitely failed mid-stream. On the SSE path — most of this proxy's traffic —
a network death was therefore byte-identical in the log to a short completion.

**FIXED** — commit _"Record a response flag when a stream fails mid-flight"_.
`LoggingBody` now classifies the body error and sets a flag before its log
line is snapshotted: an upstream that hung up is `UC`, a client that went away
is `DC`, and a body abandoned before end-of-stream is `DC` too (previously it
logged as if it had ended cleanly). A structured `WARN` carries upstream host,
cluster, bytes delivered, TTFT and elapsed, so the network origin of a failure
is legible from one line.

Two calls worth recording, because the obvious answer was wrong on both:

- **Not `UPE`.** The first analysis proposed `UpstreamProtocolError`, which
  reads plausibly but means a protocol _violation_. A TCP connection dying
  mid-body is a _termination_ — `UC`.
- **The S4 idle timeout must not collapse into `UC`.** It surfaces as
  `BodyError::Upstream(IdleTimeoutError)`, so matching on the variant alone
  reports a _stalled but alive_ upstream as a dead connection. It needs a
  `downcast_ref` to report `SI`. For LLM traffic these are entirely different
  diagnoses — a slow model versus a broken link — and merging them would have
  produced confidently wrong operator signal. Mutation-verified: removing the
  downcast fails `idle_timeout_body_error_logs_si_not_uc` and nothing else.

QA-6's `t.Skip` turned into a `PASS` with **no edit to the Go test**, which is
the point of the boundary: the suite that found the gap is what confirmed the
fix, independently of the code that produced it.

## Maintaining this document

1. **Every Go test names its case ID** in the test function name or a doc
   comment (`// QA-4: ...`), so a reader can get from a failure to the property
   it was meant to prove.
2. **A case moves to `implemented` in the same commit that adds its test**, and
   to `passing` only once it has actually run green. A registry that lags the
   suite is worse than none — it gets trusted and it is wrong.
3. **New cases require owner approval before implementation** (see "How cases
   get here"). Add them here as `proposed` first; do not write the test until
   the state says `approved`.
4. **A rejected case stays in the document with its reasoning.** The rejections
   are as useful as the approvals — they record where the black-box boundary
   sits and stop the same idea being re-proposed.
5. **When a case's premise changes** — the config surface gains a field, a
   feature it depended on lands — update the case rather than silently working
   around it in the test.

## What this suite is

Black box. It knows the built `llm-proxy` binary, a config file, and what a
client observes over the network. **It has no dependency on the Rust crates**,
and being written in Go makes that boundary physical rather than a convention —
a Go module cannot import a Rust crate by accident.

It runs its own Go mock OpenAI/Anthropic upstreams (`httptest`, with
configurable time-to-first-token and inter-chunk pacing) rather than reusing
`diffrig`'s Rust mocks, because depending on `diffrig` would drag in the proxy
crates and dissolve the boundary. Consequence to stay aware of: two mock
implementations can drift in provider fidelity, so QA mock fixtures should be
derived from **recorded real provider responses**, not from the Rust mocks.

**Which suite does a test belong to?** If it would still make sense written by
someone who has never read the source, it is QA. Proxy-behavior invariants that
need to know how the proxy works stay in `testing/diffrig`'s `mock_e2e`.

## How cases get here

Scenarios come from the repo owner, and the `qa-analyst` agent
(`.agents/agents/qa-analyst.md`, local and not versioned) proposes candidates by mining milestone ship
gates, commit messages, and the build board. **Every proposal is reviewed and
approved by the owner before any test is written.** Nothing gets implemented
off the agent's judgment alone.

---

## Approved cases

### QA-1 — Per-route token counts are correct for both providers, from one proxy and one config

**Why:** this is v0.1.0's per-route dialect claim and its acceptance criterion.
A per-listener dialect physically cannot pass it, which is what makes it proof rather than coverage.

**Config:** `llmproxy` dialect, two providers, two routes — `gpt-*` → openai,
`claude-*` → anthropic; access logs to a file, JSON format, including the four
`%LLM_*_TOKENS%` operators.

**Steps:** one request routed to each provider, against mocks returning known,
_different_ usage values per provider.

**Expected:** two access-log lines, each carrying the token counts of the
provider its route targeted. Deliberately use different numbers per provider so
a crossed-wires bug cannot pass.

**Ignored by default:** no.

---

### QA-2 — A bad config fails at load, names the offending field, and exits nonzero

**Why:** AGENTS.md invariant 1 — silently ignoring a config field is a P0. Strict mode
is a user-facing feature, and its error quality is the whole point.

**Config:** one with an unsupported/misspelled field.

**Steps:** run the binary against it.

**Expected:** nonzero exit; stderr contains the **full dotted path** of the
offending field; the process does not bind a listener. Assert on the path, not
just on failure — "it failed" would pass even if the message were useless.

**Ignored by default:** no.

---

### QA-3 — A streamed response reaches the client incrementally, not in one flush

**Why:** streaming is the product. A response that arrives correctly but all at
once passes every naive assertion while being a serious bug.

**Config:** any working single-provider config. Mock configured with a large
time-to-first-token and a small inter-chunk delay across several chunks.

**Steps:** issue a streaming request; timestamp each frame as it arrives.

**Expected:** first frame arrives no earlier than roughly the configured TTFT,
**and** the last frame arrives at least `(chunks-1) × inter_chunk_delay` after
the first. The second half is the load-bearing one: a proxy that buffered the
whole response and flushed it would deliver every frame at effectively the same
instant. Use generous tolerances — assert the shape, never tight equality.

**Ignored by default:** no.

---

### QA-4 — Provider credentials reach the upstream on every request, and never reach the access log

**Why:** two shipped P0s on the same request path, never verified together.
`request_headers_to_add` was once lowered by both front-ends and read by
nothing, so every request reached its provider with no credentials; separately,
access logging snapshots headers _before_ auth injection specifically so
credentials cannot leak into logs.

**Config:** a provider with a canary key, e.g. `api_key: sk-test-canary-value`;
access logs JSON to a file.

**Steps:** one ordinary chat-completion request through the proxy.

**Expected:** (1) the mock's captured request carries
`Authorization: Bearer sk-test-canary-value`; (2) the access-log line, read as
raw text, does **not** contain `sk-test-canary-value` anywhere. Both assertions
in one test — the two bugs are opposite failure directions on one path.

**Ignored by default:** no.

---

### QA-5 — Non-streaming responses log real byte counts and token usage, not defaults

**Why:** commit `68afb20` fixed exactly this — `content-length` responses never
received the end-of-stream flush, so no encode-filter stream-end logic ran.
That silently affects most billing-sensitive non-chat-UI traffic.

**Config:** as QA-1, with `%BYTES_SENT%` in the log format.

**Steps:** a `stream: false` request against a mock returning a body of known
length and a known `usage` block.

**Expected:** `bytes_sent` equals the exact byte length of the body the client
received (**not 0**), and the token fields equal the mock's usage exactly (not
`-`, and not `0` unless the mock said `0`).

**Ignored by default:** no.

---

### QA-6 — An upstream dying mid-stream surfaces an error, and is never retried

**Why:** a truncated 200 is a bug; a surfaced error is correct. Also encodes the
S3 rule that no retry may fire after the first response byte of a stream.

**Config:** a route with a retry policy (`retry_on: 5xx`). Mock sends 2 of 5 SSE
chunks then abruptly closes the TCP connection — no `[DONE]`, no clean FIN.

**Steps:** issue the streaming request; read until EOF or error.

**Expected:** (1) the mock's request counter is exactly **1** — no retry after
the first byte; (2) the client's read terminates in an observable error or
incomplete state, not a clean close indistinguishable from success; (3) the
access-log response-flags field is non-empty.

**Ignored by default:** no.

---

### QA-7 — SIGTERM during an active stream drains it to completion

**Why:** commit `6153e6d` fixed handlers being installed too late, so a signal
in the startup window killed the process outright with no drain. Its regression
test only checks a plain TCP accept — never an **in-flight stream**, which is
the case the drain path exists for. A deploy truncating a live SSE response is
self-inflicted, and worse than an upstream failure.

**Config:** any working config; mock paced at one chunk per ~200ms over 10
chunks.

**Steps:** start a streaming request; once 2–3 chunks have arrived, send SIGTERM
to the proxy; keep reading.

**Expected:** the client receives **all 10 chunks** and a clean stream end (no
reset); the process exits 0 within the drain timeout; an access-log line is
written for the completed request.

**Ignored by default:** no.

---

### QA-8 — A circuit-breaker-rejected request fails fast rather than queueing

**Why:** `max_requests` circuit breaking is implemented (UO response flag +
`x-envoy-overloaded`), but never verified from the client's side. A breaker that
silently queues instead of rejecting converts an overload into client-visible
latency — the opposite of its purpose.

**Config:** **an Envoy-mode bootstrap, not the `llmproxy` dialect.** As proposed
this case used `circuit_breakers: { max_requests: 1 }` in the dialect; that
field does not exist in `schema/llmproxy-v0.schema.json` or the dialect model,
so strict mode would reject the config and the test would fail for the wrong
reason. QA takes any config file, so use a bootstrap with a cluster-level
`circuit_breakers.thresholds.max_requests: 1`.

**Steps:** mock handler delays ~2s. Fire two concurrent requests to the route.

**Expected:** the second request is rejected **fast** (well under the 2s delay),
with a 503-class status and `x-envoy-overloaded` present; the first still
completes normally with its full 200 after ~2s; the rejected request's log line
carries the `UO` response flag.

**Ignored by default:** no.

---

## Rejected

- **QA-9 (content-type parameter tolerance)** — false premise. It assumed the
  usage filter's dispatch might be an exact string match, so
  `application/json; charset=utf-8` would silently fall inert and stop billing.
  `usage_filter.rs`'s `classify_body` already splits on `;` and trims, and
  `json_content_type_with_parameters_still_parses_as_json` covers it; the SSE
  path uses the same value. The _reasoning_ was right — a silent-by-design
  failure mode is exactly what QA should hunt — but this instance is handled.

Also excluded by the analyst, correctly: outlier detection and active health
checking (built and green, but not reachable from config yet — no IR wiring, so
nothing to configure black-box), retry budgets (unimplemented), ALPN defaults
(a known deliberate gap, not a regression risk), and filter-chain ordering
(internal-state assertion, already mutation-verified in the Rust suite).

---

## Implementation notes

- Suite takes the binary path from an env var, defaulting to
  `target/debug/llm-proxy` — it tests the built artifact, never the source.
  There is precedent for this mattering: a stale binary once silently passed a
  test the code failed.
- `make qa` builds the binary, then runs `go test ./...`. `make ci` invokes
  `make qa`, **skipping loudly with a visible notice if the Go toolchain is
  absent** rather than failing. The loud part is not cosmetic — a silent skip
  would let the suite rot. (Go _is_ installed on the primary dev machine as of
  2026-08-08: go1.26.5, and `make qa` runs green in ~5s. This note previously
  said it was absent.)
- Timing assertions (QA-3, QA-7, QA-8) must assert shape with generous
  tolerance, never tight equality, and should be loop-verified before landing.

---

### QA-10 — TTFT and TPOT reach the access log, with values that match the upstream's pacing

**Why:** v0.1.0's ship gate names these explicitly — "token counts _and
TTFT/TPOT_ reach the access log for live traffic" — and until 2026-08-08 the
TPOT half could not be satisfied at all through the `llmproxy` dialect: the operators
`%LLM_TPOT%`, `%LLM_MAX_STALL%` and `%LLM_RESPONSE_CHUNKS%` were built, but no
dialect log format ever emitted them. QA-1 reads the token fields out of the
same log line and never looks at the latency ones.

There is a sharper reason than coverage. **TPOT has already shipped one silent
bug of exactly the shape a black-box test catches:** it divided in integer
milliseconds, so it rendered `0` for fast providers (1000–2000 tok/s) —
reading zero precisely when performance was best. It was fixed by dividing in
micros, but nothing outside a unit test guards it, and `0` in a log field looks
entirely plausible to a reader. Only an assertion against a mock with _known_
pacing can tell a real measurement from a broken one.

**Config:** `llmproxy` dialect, single provider, JSON access log to a file —
the dialect's default format, so this also proves the default carries these
fields rather than a hand-written format doing the work.

**Steps:** one streaming request against a mock paced with a large
time-to-first-token and a known inter-chunk delay across several chunks (QA-3's
pacing setup is the template).

**Expected:** the request's access-log line carries

- `llm_ttft_ms` at roughly the configured TTFT (generous lower bound),
- `llm_tpot_ms` **strictly greater than zero** and in the neighbourhood of the
  configured inter-chunk delay — the non-zero half is the load-bearing
  assertion, since that is the regression that already happened once,
- `llm_response_chunks` equal to the number of chunks the mock sent.

Timing assertions are shape-with-tolerance, never tight equality, per this
document's own standing rule.

**Ignored by default:** no.

## QA-11 — Redis spend migration/restart

Run against a disposable Redis instance with no authentication:

```sh
QA_REDIS_ADDR=127.0.0.1:6379 make qa-case CASE=TestQA11
```

Without `QA_REDIS_ADDR`, this case explicitly skips. With it, a connection
failure fails the case. The test uses a unique namespace and removes only its
own rows. The harness supervises both proxy processes and bounds network calls.

The fixture seeds the existing Redis tenant budget/spend format and two stable
keys under that tenant. The explicit cutover policy starts fresh key ceilings;
legacy aggregate history cannot establish individual key charges. Both keys must
start at zero, and the legacy budget and historical total must remain unchanged.
Key A reaches its ceiling, then the test waits for Redis to acknowledge the
charge before sending SIGKILL. The restarted binary uses the same writer ID and
must retain A's budget/history, deny A, and admit B independently. Raising A's
ceiling allows one more charge; its persisted total and writer sequence must
advance without loss or duplication. Denied requests never reach the upstream.

This proves the current compatible row layout and an explicit fresh-key cutover,
not a general migration tool or evidence-based historical per-key seeding. It
does not recover an unflushed RAM backlog after SIGKILL, exercise a Redis
partition, or prove three-process convergence; QA-12 covers those separately.

QA-11 also rotates A's secret through the admin API, verifies the old secret is
rejected and the same budget/history remains, and rejects ownership changes
and revoked ID reuse.

## QA-12 — Redis partition and checkpointed process recovery

Run `QA_REDIS_ADDR=127.0.0.1:6379 make qa-case CASE=TestQA12` against disposable
Redis. Missing configuration skips explicitly; connection failure fails.

Three supervised proxy processes share one namespace, with distinct stable
writer IDs and recovery journal paths. Baseline charges converge to $6 with
each writer's own sequence advancing. A TCP relay then closes existing Redis
connections and refuses new ones. Each replica reports stale reconciliation,
admits one local $2 charge, and rejects the next at its local $8 ceiling.

The drill waits for a durable journal checkpoint of the outage charge before
SIGKILL of one replica. Restoring the same Redis address and restarting that
replica with the same writer ID and journal must replay all deltas exactly once:
every replica converges to $12, clears pending rows and reconciliation expiry,
and denies further requests. A second clean restart must retain $12 without
duplication. The test bounds calls, supervises processes, and removes its own
namespace. Charges accrued after the last checkpoint remain volatile; this
does not claim synchronous per-request durability.

## QA-13 — Billing ledger across a crash and at its disk cap

Approved through the billing ledger's acceptance (ADR-0009). `qa13_billing_ledger_test.go`
drives a dialect config with a `ledger` block, `--service-node`, an admin
listener and a Go mock OpenAI upstream, through the listener and the admin API
only. No external service is needed.

`crates/proxy/tests/ledger_e2e.rs` already covers, against the same binary, a
SIGTERM restart opening a later epoch, the startup and reload refusals, one
read+ack page, and the reconciliation counters (including `admit` with every
slot held). QA-13 adds what that file never switches on:

- **SIGKILL under load.** Four clients keep sending; a consumer reads (twice,
  to show reading does not consume) and does not acknowledge; the proxy is
  killed with requests in flight. After a restart every entry read before the
  kill is returned again (committed means durable; unacknowledged means
  redelivered), the killed epoch is gapless from `seq` 0 and no longer than
  the requests served, and the restart's first entry is `seq` 0 in a later
  epoch. One acknowledgement through the last cursor then empties the ledger.
- **`reject` at `max_disk_bytes`.** With a 2 MiB cap, requests continue until
  one is answered `503` with the body `billing ledger unavailable: disk_full`.
  A request at the cap never reaches the provider, and
  `llmproxy_ledger_rejected_total{reason="disk_full"}` counts. The consumer
  acknowledges until `admitting` is true; the next request is served without a
  restart, every served request is committed, and none is counted lost.
- **`admit` at `max_disk_bytes`.** Every request is served and dialled;
  `llmproxy_ledger_unledgered_total{reason="disk_full"}` rises and the
  suppressed warning reaches the log. After acknowledgement, committed plus
  unledgered equals served.

At the cap the acknowledgement itself can be refused with `507` (it needs
spool space too). The test's consumer then halves the acknowledged prefix, as
the docs tell a consumer to; the case logs how many acknowledgements were
refused. A run on 2026-10-17 under load hit it on the first full-range ack.

Entries lost to the crash window (the last `group_commit_interval`) are not
counted exactly: the client cannot see which served requests had committed.
The case logs served versus committed for the killed epoch.

## QA-14 — Trace export captures an opted-in tenant only

**Property.** With `observability.traces` writing to a directory and two
tenants created over the admin API, only the tenant that opted in through
`PUT /tenants/{id}/trace_export` gets a trace. The line carries the request
body the client sent and the streamed response reassembled into one chat
completion, with a `complete` capture state; the other tenant produces no
line. Segments are sealed by SIGTERM and read as gzip JSON lines.

**Why black box.** The Rust tests drive the tee, the exporter and the binary
separately; this one checks the documented surface end to end: the dialect
block, the admin opt-in, the on-disk layout and the line a consumer reads.
