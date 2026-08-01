# QA scenarios — the registry

**Suite:** `testing/qa/` (Go). This document is the **spec the suite is written
from**, and it is tracked in git (via an explicit `.gitignore` exception) so it
can be reviewed alongside the tests that cite its case IDs.

## Status

| Case | Property | State |
|------|----------|-------|
| QA-1 | Per-route token counts, both providers, one config | implemented — **partially passing**, token half skipped (see below) |
| QA-2 | Bad config fails loudly with the field path, exits nonzero | passing |
| QA-3 | Streamed response arrives incrementally | passing |
| QA-4 | Credentials reach upstream, never reach the log | passing |
| QA-5 | Non-streaming responses log real bytes and tokens | approved |
| QA-6 | Upstream dying mid-stream errors, and is not retried | passing |
| QA-7 | SIGTERM during an active stream drains to completion | passing |
| QA-8 | Circuit-breaker rejection fails fast, does not queue | approved |
| QA-9 | ~~Content-type parameter tolerance~~ | rejected — see below |

States: `proposed` → `approved` → `implemented` → `passing`. Nothing skips
`approved`.

### QA-1 found two independent gaps — one now fixed, one outstanding

On its very first run, QA-1 established that both providers receive exactly one
request each (routing and provider dispatch work end to end), and then **the
configured access-log file was never created at all**. Two separate things were
in the way:

1. ~~**The `llmproxy` dialect never wires `observability.access_logs` into the
   generated Envoy config.**~~ **FIXED** — commit *"Emit access logs from the
   llmproxy dialect"*. `crates/proxy-simple-config/src/lower.rs` used to emit
   only a warning (*"access logging is recorded but not emitted yet (WP-24)"*)
   and never add an `access_log` entry to the HCM. That warning was **stale**:
   WP-24 had landed and access logging worked fully in Envoy mode; only the
   dialect lowering was missing, so a proxy configured the way users actually
   configure it produced **no access logs whatsoever**.
2. **WP-33 — still outstanding.** The usage filter isn't in the dialect's
   generated `http_filters`, so every `%LLM_*_TOKENS%` operator renders as the
   absent-value `-`. See `docs/wp-33-design-brief.md`.

Gap 1 was not anticipated by the code review that produced the WP-33 brief —
an independently written black-box test found it from the outside. That is the
argument for this suite existing, and it arrived on day one.

**QA-1's current shape.** Rather than being all-or-nothing on the token counts,
it now asserts everything that does not depend on WP-33 — two log lines, one
per route, correct `path`, `response_code` 200, `bytes_sent` > 0 — and degrades
to a loud `t.Skip` naming WP-33 only for the token assertions. The access-log
file failing to appear is now a hard failure, since that is a regression of the
fix above. It tightens automatically as WP-33 lands.

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
missing the request method too. Fixed in *"Resolve Envoy pseudo-headers in
access-log REQ/RESP operators"* — `LogContext` now carries the pseudo-headers
as typed fields, `%RESP(:STATUS)%` works, and the unfaithful
`x-envoy-original-path` injection is gone.

Worth noting how this one hid: `header_lookup`'s own doc comment *described*
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
`ResponseFlag` when the response *body* subsequently errored —
`LoggingBody::poll_frame` discarded the error outright (`Err(_)`), so the line
rendered `response_flags` as the absent-value `-` even though the request had
definitely failed mid-stream. On the SSE path — most of this proxy's traffic —
a network death was therefore byte-identical in the log to a short completion.

**FIXED** — commit *"Record a response flag when a stream fails mid-flight"*.
`LoggingBody` now classifies the body error and sets a flag before its log
line is snapshotted: an upstream that hung up is `UC`, a client that went away
is `DC`, and a body abandoned before end-of-stream is `DC` too (previously it
logged as if it had ended cleanly). A structured `WARN` carries upstream host,
cluster, bytes delivered, TTFT and elapsed, so the network origin of a failure
is legible from one line.

Two calls worth recording, because the obvious answer was wrong on both:

- **Not `UPE`.** The first analysis proposed `UpstreamProtocolError`, which
  reads plausibly but means a protocol *violation*. A TCP connection dying
  mid-body is a *termination* — `UC`.
- **The S4 idle timeout must not collapse into `UC`.** It surfaces as
  `BodyError::Upstream(IdleTimeoutError)`, so matching on the variant alone
  reports a *stalled but alive* upstream as a dead connection. It needs a
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
(`.claude/agents/qa-analyst.md`) proposes candidates by mining milestone ship
gates, commit messages, and the build board. **Every proposal is reviewed and
approved by the owner before any test is written.** Nothing gets implemented
off the agent's judgment alone.

---

## Approved cases

### QA-1 — Per-route token counts are correct for both providers, from one proxy and one config

**Why:** this is v0.1.0's per-route dialect claim and the acceptance criterion
in `docs/wp-33-design-brief.md`. A per-listener dialect physically cannot pass
it, which is what makes it proof rather than coverage.

**Config:** `llmproxy` dialect, two providers, two routes — `gpt-*` → openai,
`claude-*` → anthropic; access logs to a file, JSON format, including the four
`%LLM_*_TOKENS%` operators.

**Steps:** one request routed to each provider, against mocks returning known,
*different* usage values per provider.

**Expected:** two access-log lines, each carrying the token counts of the
provider its route targeted. Deliberately use different numbers per provider so
a crossed-wires bug cannot pass.

**Ignored by default:** no.

---

### QA-2 — A bad config fails at load, names the offending field, and exits nonzero

**Why:** ground rule #1 — silently ignoring a config field is a P0. Strict mode
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
access logging snapshots headers *before* auth injection specifically so
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
  path uses the same value. The *reasoning* was right — a silent-by-design
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
  absent** rather than failing. The loud part is not cosmetic — Go is currently
  not installed on the primary dev machine, which is exactly the situation
  where a silent skip would let the suite rot.
- Timing assertions (QA-3, QA-7, QA-8) must assert shape with generous
  tolerance, never tight equality, and should be loop-verified before landing.
