# Known behavior divergences from Envoy

Every intentional or accepted behavioral difference from the pinned Envoy version is
recorded here, with justification and the diff-rig fixture that pins it. An
undocumented divergence found by the rig is a bug.

| # | Area | Envoy behavior | Our behavior | Justification | Pinned fixture |
|---|------|----------------|--------------|---------------|----------------|
| — | — | — | — | — | — |

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
