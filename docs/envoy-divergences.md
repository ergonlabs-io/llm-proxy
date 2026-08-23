# Known behavior divergences from Envoy

Every intentional or accepted behavioral difference from the pinned Envoy version is
recorded here, with justification and the diff-rig fixture that pins it. An
undocumented divergence found by the rig is a bug.

| # | Area | Envoy behavior | Our behavior | Justification | Pinned fixture |
|---|------|----------------|--------------|---------------|----------------|
| 1 | `--drain-strategy` | `gradual` ramps the probability an in-flight response is closed linearly over the drain window; `immediate` closes at 100% from the start of the drain. | `gradual` and `immediate` are byte-identical: the drain sequence only ever waits for the connection registry to empty or the drain deadline to pass, then flips a plain shutdown signal hyper's `graceful_shutdown()` reacts to. `DrainState::drain_close_probability` implements the ramp but has no call site. | Wiring it properly requires the HTTP codecs (`proxy-http`) to consult a per-response close probability, which is its own work package, not a contained fix — see "Drain strategy" below. A silent no-op would violate ground rule #1, so this is a loud startup `tracing::warn!` instead (`crates/proxy/src/main.rs`, `serve`). | none yet — tracked by `crates/proxy-core/src/drain.rs`'s own unit tests on `drain_close_probability` plus the startup warning; no diff-rig fixture exists for drain timing yet. |
| 2 | `%RESPONSE_FLAGS%` | All 20 documented flags can fire under the conditions Envoy defines for them. | 6 of 20 are genuinely unreachable (no corresponding feature exists) and 1 more (`DC`) is declared and apparently wired but is dead code (its only producer is never actually constructed; `UR` was the second such flag until the h2 refused-stream decode gave it a real producer) — see "Response flags (WP-24)" below for the full per-flag table. | Most of the 6 name features not yet built (`ext_authz`, gRPC ratelimit service, strict header validation, `max_stream_duration`, a downstream/upstream health-check surface) — see ground rule #1's spirit: rather than silently claim coverage, each is documented with the specific reason so the next audit doesn't re-derive it. | `crates/proxy-observability/src/flags.rs`'s per-variant doc comments (normative); `crates/proxy-http/tests/response_flags.rs`, `router_retry.rs`, `router_access_log.rs`, and `proxy-filters`' `token_limit_filter.rs` pin the 11 reachable flags. |
| 3 | Listener stat naming | Listener stats are keyed by the listener's resolved **address** (`listener.0.0.0.0_80.downstream_cx_total`), unless a `Listener.stat_prefix` is configured, in which case that is used instead. | Keyed by the configured listener **name**, always (`listener.ingress_http.downstream_cx_total`). There is no `stat_prefix` handling. | The attribute the instrument carries is the name (`DOWNSTREAM_CX_TOTAL.attribute_keys = ["listener"]`), and the address is not available where the counter is recorded — `spawn_accept_loop` knows the listener by name. A name is also stable across a rebind, where an address is not, and it matches how this proxy already keys cluster stats (`cluster.<name>.upstream_rq_total`, which IS Envoy's own scheme for clusters). Recorded as a divergence rather than resolved because changing it means threading the bound address down to the recording site, which is a larger change than this gap warranted. | `envoy_render::tests::downstream_cx_total_renders_under_the_listener_name` (unit) and `crates/proxy/tests/stats_e2e.rs::served_requests_are_reflected_in_stats` (e2e, asserts `/stats` and `/stats/prometheus` agree). |

## CLI flag policy

llm-proxy is a standalone LLM proxy competing in the LLM-gateway space — Envoy
(pinned v1.38) is our maturity bar and the semantic reference for the config
surface we share, not a product we are replacing. For Envoy CLI flags, that
means:

- **Implemented flags** behave per the pinned Envoy docs.
- A flag whose purpose is **vacuously satisfied** by our architecture may be
  accepted and ignored with a *self-explaining* warning (say why ignoring it is
  safe, not just that it happens). Example: `--base-id` namespaces Envoy's
  shared-memory hot-restart regions; we have no shared memory (ADR-0001:
  restarts are SO_REUSEPORT process overlap), so multiple instances per host
  are already safe and the flag protects nothing.
- A flag whose intent we **cannot honor** must be rejected with an error naming
  the alternative — never accepted and ignored. Example (when it comes up):
  `--restart-epoch` — hot-restart wrapper scripts passing it expect coordinated
  socket-handoff semantics; accepting it while doing process-overlap restarts
  would silently break their protocol.
- **Unknown flags** fail loudly (clap rejects them).

The test for "vacuous vs. cannot-honor": *could ignoring this flag change any
behavior an operator or wrapper script depends on?* If yes, reject.

`--drain-strategy` (below) is a fourth case the three bullets above don't
name: the flag's intent is honorable in principle (nothing about our
architecture rules it out, unlike `--base-id`'s shared memory or
`--restart-epoch`'s socket handoff), it just isn't wired up yet. Silently
accepting it would still violate ground rule #1 — the fix is to warn loudly
rather than pretend it's vacuous or reject a flag we could someday honor.

## Drain strategy

`--drain-strategy gradual|immediate` (found 2026-08-09, table row 1) is
accepted and threaded all the way down to `DrainState`, but the two values
produce **identical** observable behavior today. The drain sequence
(`graceful_shutdown` in `crates/proxy-core/src/drain.rs`) does exactly this,
regardless of `strategy`:

1. Wait for the worker's `ConnectionRegistry` to empty, or the drain deadline
   (`--drain-time-s`) to pass — whichever comes first.
2. Flip a plain boolean shutdown signal, which the HTTP codecs
   (`proxy-http::codec::{serve_http1,serve_http2}`) treat as "stop accepting
   further requests on this connection and let hyper's own
   `graceful_shutdown()` close it once the current response finishes."

`DrainState::drain_close_probability` is the seam a per-response close
decision was meant to consult — it correctly implements the gradual ramp (see
its doc comment and `crates/proxy-core/src/drain.rs`'s unit tests) — but
nothing calls it. An in-flight response is never cut off at the deadline
either way (a deliberate choice, not part of this gap): Envoy's own
`drain_strategy` only affects when NEW requests are told to close, never
active ones.

Wiring this up for real means teaching `serve_http1`/`serve_http2` to consult
`drain_close_probability` per response and set `Connection: close` (HTTP/1)
or send a `GOAWAY` (HTTP/2) probabilistically during the drain window — a
change to `proxy-http`'s codecs and their keep-alive handling, not a
one-line fix to `proxy-core`. Until that lands, `llm-proxy serve` emits a
startup `tracing::warn!` naming the gap (`crates/proxy/src/main.rs`, `serve`)
whenever it starts serving, so the inertness is loud rather than discovered
by an operator comparing drain timing against Envoy's.

## TLS inspector auto-injection

Not a divergence — Envoy parity. If a `Listener` has a filter chain whose
`filter_chain_match` keys on `server_names` (SNI), `application_protocols`
(ALPN), or `transport_protocol: tls`, but no `tls_inspector` listener filter
is configured, Envoy auto-inserts a default one so those criteria have
something to populate. We match that behavior in `lower.rs`
(`convert_listener_filters`): omitting it would make the match criteria
silently never match TLS traffic, which is a worse divergence than the
injection. See the `ListenerFilterSpec` doc comment in
`crates/proxy-config/src/ir.rs` and the `auto_injects_tls_inspector_for_*`
tests in `crates/proxy-config/tests/listener_filters.rs`.

Separately: we reject a `tls_inspector` config that sets `enable_ja3_fingerprinting`,
`enable_ja4_fingerprinting`, `initial_read_buffer_size`, or
`close_connection_on_client_hello_parsing_errors` (naming the field path)
rather than silently accepting and ignoring them — ground rule #2. Only
`max_client_hello_size` is implemented.

## Response flags (WP-24)

WP-24's acceptance criterion is "every response flag reachable by at least
one test." Re-audited flag by flag (2026-08-22) against what this codebase
actually builds — a `grep` for `set_response_flag` is not proof of
reachability, as two rows below found the hard way. The normative version of
this table is the per-variant doc comments on `ResponseFlag` itself
(`crates/proxy-observability/src/flags.rs`); this is the narrative form.

| Flag | Code | Status | Detail |
|---|---|---|---|
| `NoHealthyUpstream` | `UH` | Reachable, tested | Zero endpoints (or every host filtered) makes `select_host` return `None`. `response_flags::zero_endpoints_records_and_renders_the_uh_flag`. |
| `UpstreamConnectionFailure` | `UF` | Reachable, tested | Refused TCP connect, or a TLS handshake failure (folded into the same code). `response_flags::a_refused_connection_records_and_renders_the_uf_flag`. |
| `UpstreamOverflow` | `UO` | Reachable, tested | The S5 `max_requests` circuit breaker. `router.rs` also has a `PoolError::Overflow` arm for this flag, but nothing ever constructs that variant — the breaker is the only live producer. `response_flags::max_requests_zero_records_and_renders_the_uo_flag`. |
| `NoRouteFound` | `NR` | Reachable, tested | A request path matching no configured route. `response_flags::no_route_matched_records_and_renders_the_nr_flag`. |
| `UpstreamRetryLimitExceeded` | `URX` | Reachable, was unwired — now fixed | The S3 retry engine exists, but nothing ever set this flag when its budget ran out. Fixed by `RetryState::retry_limit_exceeded` (`proxy_http::retry`) plus `router.rs`'s `record_retry_limit_exceeded_if_applicable`, called at every attempt-failure exit right after that exit's own flag, so a combined line renders `<flag>,URX` (matching Envoy, which never puts `URX` first). Deliberately distinct from "`should_retry` returned false": that's also true for an outcome the policy was never configured to retry, or a body S3.4 ruled unretriable — neither of those is a *limit* being exceeded. `router_retry::retry_limit_exceeded_renders_the_urx_response_flag` and the negative case `a_successful_retry_never_renders_urx`. |
| `NoClusterFound` | `NC` | Reachable, tested | A route forwarding to an unregistered cluster name. `router_access_log::unknown_cluster_records_and_renders_the_nc_flag`. |
| `DownstreamConnectionTermination` | `DC` | **Looks wired, unreachable today** | `BodyError::Downstream` is constructed in exactly one place — `codec.rs`, reading the incoming *request* body — and `filter_manager.rs`'s `collect_request` discards that error entirely (`.map_err(\|_\| ())`) before any `StreamInfo` exists to flag; the resulting 400 carries no flag. `access_logging.rs`'s `LoggingBody::classify` does map this variant to `DC` and has its own unit test (`downstream_body_error_mid_stream_logs_dc`), but that test hand-constructs a `BodyError::Downstream` directly — nothing in the real response-body pipeline `LoggingBody` wraps can ever produce one (it only ever sees `BodyError::Upstream`). **Fix candidate for a future batch**: thread the real error through `collect_request` (instead of `Result<_, ()>`) and set `DC` on the resulting 400, in `filter_manager.rs` — out of this batch's file scope. |
| `FailedLocalHealthCheck` | `LH` | Unreachable | No downstream health-check filter or admin/maintenance-mode surface exists. |
| `UpstreamRequestTimeout` | `UT` | Reachable, tested | The route's whole-loop `timeout`, or a `per_try_timeout` on a single attempt. `response_flags::a_route_timeout_records_and_renders_the_ut_flag`. |
| `LocalReset` | `LR` | Unreachable | No code path resets a connection on the proxy's own initiative outside the cases other flags already model (client gone is `DC`'s condition, an idle upstream is `SI`, an upstream failure is `UF`/`UC`/`UR`). |
| `UpstreamRemoteReset` | `UR` | Reachable, was dead code — now fixed | An h2 `RST_STREAM(REFUSED_STREAM)` is a deliberate remote reset, and since the codec learned to decode RST_STREAM reasons it flags `UR` rather than `UC`. `response_flags::a_refused_h2_stream_records_and_renders_the_ur_flag`. **The other route to this flag is still dead**: `PoolError::ResetBeforeHeaders` is constructed by neither `ConnectPool::new_stream` (h1) nor the h2 connection cache, so a post-connect TCP reset still reports as `UF`. Distinguishing it (match `ECONNRESET` specifically after a successful connect) remains a classification decision, not a wiring fix. |
| `UpstreamConnectionTermination` | `UC` | Reachable, tested | Any hyper-level failure sending the request or parsing the response. `response_flags::a_garbled_upstream_response_records_and_renders_the_uc_flag`. |
| `RateLimited` | `RL` | Reachable, was unwired — now fixed | `token_limit_filter` denied requests with **zero** occurrences of `ResponseFlag` in the file — its own refusal was indistinguishable from any other 429 in the access log. Fixed: set on the deny path only (never on the fail-open paths, which admit the request). `token_limit_filter::tests::a_denied_request_renders_the_rl_response_flag`. |
| `UnauthorizedExternalService` | `UAEX` | Unreachable | No `ext_authz` filter exists (WP-32, not yet built). |
| `RateLimitServiceError` | `RLSE` | Unreachable | No external gRPC ratelimit service (Envoy's RLS protocol, WP-32) is implemented; `token_limit_filter` is a local/in-process limiter with no remote service to fail. |
| `InvalidEnvoyRequestHeaders` | `IH` | Unreachable | No strict-header-validation feature exists. |
| `StreamIdleTimeout` | `SI` | Reachable, tested | A route's `idle_timeout` firing while an upstream response body has gone quiet. `response_flags::an_idle_response_body_records_and_renders_the_si_flag`. |
| `DownstreamProtocolError` | `DPE` | Unreachable | A malformed downstream request is a connection-level failure inside `codec.rs`'s `serve_http1`/`serve_http2` (`CodecError`), returned before any per-request `StreamInfo` exists — there is no stream to flag. |
| `UpstreamProtocolError` | `UPE` | Unreachable today | `UpstreamCodecError` does not classify `hyper::Error` by kind; a genuine protocol violation and a plain connection drop both collapse into the same variants, already mapped uniformly to `UC`. Buildable via `hyper::Error::is_parse()`, but which hyper error kinds count as "protocol" versus "connection" (matching Envoy's own `UPE`/`UC` split) is a classification decision. |
| `UpstreamMaxStreamDurationReached` | `UMSDR` | Unreachable | No `max_stream_duration` feature (distinct from `timeout`/`idle_timeout`, both of which exist) is implemented. |

Two rows above (`DC`, `UR`) are the reason this table exists rather than a
comment saying "see the code": both look reachable from a `grep` for
`set_response_flag` — the flag-setting `match` arm is right there — and
both are dead code once you trace back to what actually constructs the
value that arm matches on. A future audit that only greps for the flag name
will reach the same wrong conclusion these did on the first pass.


## Listener stat naming (WP-23 increment 6b follow-up)

`downstream_cx_total` is a real Envoy stat, and until 2026-08-22 the
Envoy-text `/stats` endpoint omitted it entirely while `/stats/prometheus`
reported it correctly. `envoy_render::envoy_counter_name` simply had no case
for the instrument, and its `_ => None` arm — correct policy for `gen_ai.*`,
which genuinely has no Envoy equivalent — silently swallowed one that does.

Two things are worth carrying from that:

- **Two renderers over one registry can disagree, and a test that checks only
  one will not notice.** The e2e test now asserts both endpoints report the
  same count for the same listener.
- **A catch-all arm whose policy is "omit what has no equivalent" cannot tell
  that apart from "we forgot to add a case."** Anything added to
  `stats.rs`'s `instruments` module that mirrors an Envoy stat needs an
  `envoy_counter_name`/`envoy_histogram_name` arm at the same time.

The remaining divergence is the key. Envoy keys listener stats by address;
this renders the configured listener name. See the table row above for why —
briefly, the name is what the recording site has, and it is what this proxy
already uses for cluster stats.
