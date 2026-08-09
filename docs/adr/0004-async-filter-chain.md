# ADR 0004 — Async filter chain: the router becomes a terminal filter

**Status:** proposed (2026-07-27)

## Context

Envoy has one uniform model: the HTTP filter manager owns the stream, every
element of the chain is an `Http::StreamFilter`, and the **router is simply the
terminal one** (`Router::Filter`, a `StreamDecoderFilter`). It owns no stream
state of its own — it reads `callbacks_->route()` and `callbacks_->streamInfo()`
like any other filter. Access logging fires above the chain at `ActiveStream`
completion.

We diverged. `RouterHandler` is a `StreamHandler` sitting *behind* a seam
(`FilterManager::run` calls `terminal.handle(req).await`), because routing is
async and our `HttpFilter` callbacks are synchronous. That seam has already
produced three shipped bugs, all found by the first socket-level test that
exercised a filter and the access log together (fixed in `68afb20`):

1. Two disconnected `StreamInfo` objects — filter writes were invisible to the
   access log, including `is_local_reply` and `response_code_details`.
2. `LoggingBody` nested *inside* `StreamingEncoder`, so the log rendered before
   the encode chain saw `end_stream`.
3. `content-length` responses never received the end-of-stream flush at all.

Those are fixed, but the seam that produced them remains, and it still costs us
concretely:

- **`DecoderCallbacks::route()` always returns `None`.** `ChainCtx.route` is
  never populated (`filter_manager.rs:1860`); `clear_route_cache` clears
  nothing. The router resolves its own route privately. **This makes per-route
  filter config (`typed_per_filter_config`) impossible** — which Lane H needs
  for per-route provider dialect (WP-33/34) and for WP-35 model routing.
- **No decode filter can perform asynchronous work.** `ext_authz` (WP-32) is
  inherently an async decode filter: it must pause the chain, call an external
  service, and resume. There is no way to express that today.
- Two construction and lifecycle models. The router is not built by a
  `FilterInstanceFactory`, never gets `on_destroy`, and needed a bespoke
  `HttpRequestParts.stream_info` field to be handed the shared `StreamInfo`.

The encode direction is *already* event-driven — `StreamingEncoder::poll_frame`
drives encode filters per frame from a `Body` impl. Only the decode direction is
a straight-line `async fn`.

## Decision

**Make the decode chain asynchronous, and make the router a terminal
`HttpFilter` in it.**

### 1. Filters may yield asynchronous work

The existing synchronous callbacks are unchanged — a filter that does not need
async keeps compiling untouched, and `FilterHeadersStatus` / `FilterDataStatus`
keep their present meanings. One method is added to `HttpFilter`:

```rust
/// Asynchronous continuation, polled by the manager after this filter has
/// returned a `StopIteration*` status. `Some(fut)` means "I have work in
/// flight; await it, then re-drive the chain from me". `None` (the default)
/// keeps today's meaning: stopped until someone calls `continue_decoding()`.
///
/// Rust note: a boxed, pinned, `!Send` future — the same shape `StreamHandler`
/// already uses, and for the same reason (an `async fn` in a trait is not
/// object-safe). `!Send` is correct per ADR-0003: the whole stream lives on
/// one worker's `LocalSet`.
fn poll_pending<'a>(
    &'a mut self,
) -> Option<Pin<Box<dyn Future<Output = ()> + 'a>>> {
    None
}
```

Anything a filter needs from its callbacks must be captured *before* returning
the future — the future borrows only the filter. Results are applied on the
next synchronous callback, when callbacks are available again. This is the
constraint that keeps the borrow checker satisfied without `Rc<RefCell<_>>`
around the whole chain, and it is the one real ergonomic difference from
Envoy's model, where `callbacks_` is held throughout.

### 2. The terminal filter produces the response

```rust
pub trait TerminalHttpFilter: HttpFilter {
    /// Called once the decode chain has reached this filter with the complete
    /// request. Produces the response, which the manager then drives into the
    /// ENCODE chain — exactly the position Envoy's `Router::Filter` occupies.
    fn respond<'a>(
        &'a mut self,
        cb: &'a mut dyn DecoderCallbacks,
    ) -> Pin<Box<dyn Future<Output = HttpResponseParts> + 'a>>;
}
```

`RouterHandler` implements this instead of `StreamHandler`. It is built by a
`FilterInstanceFactory` like every other filter, lives in the `filters` vec at
position `n-1`, receives `on_destroy`, and reads the shared `StreamInfo` and the
cached route through `DecoderCallbacks` rather than through bespoke plumbing.

### 3. The filter manager owns route resolution (S2.8)

`ChainCtx.route` is populated lazily on first `DecoderCallbacks::route()`,
resolved against the route table the manager holds. `clear_route_cache()`
genuinely invalidates it, and the next `route()` re-resolves — the S2.8
contract. The router stops resolving privately and reads `cb.route()`.

This is what unblocks `typed_per_filter_config`.

### 4. `drive_decode` becomes `async fn`

It gains an await point around `poll_pending`. `FilterManager::run` stays a
linear `async fn`: we are **not** converting to a callback/event-loop machine.
The chain is driven by an explicit position cursor that already exists in the
encode direction; awaiting inside the driver is sufficient to express
"filter pauses, work happens, chain resumes" without inverting control flow.

## Consequences

**Gained:** `route()` works for every filter, so per-route filter config becomes
possible (Lane H WP-33/34/35). Async decode filters become expressible
(`ext_authz`, WP-32). One construction, lifecycle, and callback model. The
`HttpRequestParts.stream_info` field and the `terminal: Rc<dyn StreamHandler>`
member both disappear.

**Cost:** `HttpFilter` and `DecoderCallbacks` are frozen shared surfaces
(ground rule #4); this changes both. Every lane codes against them. `router.rs`
and `filter_manager.rs` are the two largest and most semantically delicate files
in the repo, and S2's iteration semantics must survive the move intact — the
existing S2 test suite is the guard, and test *counts* must be checked, not just
the green (CLAUDE.md rule 9).

**Deliberately not done:** full inversion of control into an Envoy-style event
loop. It buys nothing our linear-async driver cannot express, and it would make
every stack trace and every test harder to follow.

## Migration plan

Sequenced so the suite is green at every step:

1. **Route resolution up.** Manager resolves and caches; `route()` returns real
   values; `clear_route_cache` works. Router still a `StreamHandler`, now
   reading `cb.route()`. Independently valuable, and lands the Lane H unblock
   early.
2. **`poll_pending` + async `drive_decode`.** No behavior change yet; a test
   filter proves an async decode filter can pause and resume the chain.
3. **`TerminalHttpFilter`; router moves into the chain.** Delete the
   `terminal: Rc<dyn StreamHandler>` seam and `HttpRequestParts.stream_info`.
4. **Per-route filter config** on top of (1), as its own work package.

## Alternatives considered

- **Keep the seam, patch symptoms.** Rejected: three bugs already, and it
  structurally blocks per-route config and async decode filters.
- **Make only the terminal async-capable** (a terminal-shaped escape hatch,
  leaving other filters synchronous). Cheaper and delivers the route-cache and
  uniformity wins, but leaves `ext_authz` inexpressible — it would force this
  same decision again later, with more code depending on the old shape.
