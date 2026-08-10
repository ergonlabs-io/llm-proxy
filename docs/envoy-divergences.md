# Known behavior divergences from Envoy

Every intentional or accepted behavioral difference from the pinned Envoy version is
recorded here, with justification and the diff-rig fixture that pins it. An
undocumented divergence found by the rig is a bug.

| # | Area | Envoy behavior | Our behavior | Justification | Pinned fixture |
|---|------|----------------|--------------|---------------|----------------|
| 1 | `--drain-strategy` | `gradual` ramps the probability an in-flight response is closed linearly over the drain window; `immediate` closes at 100% from the start of the drain. | `gradual` and `immediate` are byte-identical: the drain sequence only ever waits for the connection registry to empty or the drain deadline to pass, then flips a plain shutdown signal hyper's `graceful_shutdown()` reacts to. `DrainState::drain_close_probability` implements the ramp but has no call site. | Wiring it properly requires the HTTP codecs (`proxy-http`) to consult a per-response close probability, which is its own work package, not a contained fix — see "Drain strategy" below. A silent no-op would violate ground rule #1, so this is a loud startup `tracing::warn!` instead (`crates/proxy/src/main.rs`, `serve`). | none yet — tracked by `crates/proxy-core/src/drain.rs`'s own unit tests on `drain_close_probability` plus the startup warning; no diff-rig fixture exists for drain timing yet. |

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
