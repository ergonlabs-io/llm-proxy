---
title: Failover and aggregates
summary: What a route's `fallbacks` list actually does — the aggregate
  cluster it lowers to, the same-dialect requirement, and how retry budget
  and member order interact.
last_updated: 2026-08-23
related:
  - ../providers-and-routing/providers-and-clusters/
  - ../providers-and-routing/timeouts-and-retries/
  - ../configuration/configuration-file/
---

# Failover and aggregates

A route's `fallbacks` list names providers tried, in order, when the primary
fails. This is implemented and tested end to end, not a warned-and-dropped
field.

## What `fallbacks` lowers to

A route with `fallbacks` gets an extra cluster: an `envoy.clusters.aggregate`
named `fallback:route-<index>`, whose member list is the primary provider's
cluster followed by each fallback's cluster, in the order listed. The route's
own `cluster` action then points at the aggregate instead of the primary
directly (`crates/proxy-simple-config/src/lower.rs`'s `lower_route`, proven
by `one_fallback_emits_an_aggregate_with_members_in_order` and
`route_with_fallback_targets_the_aggregate_not_the_primary` in
`crates/proxy-simple-config/tests/fallbacks.rs`). A route with no `fallbacks`
is unaffected: it still targets `provider:<name>` directly, and no aggregate
cluster is emitted at all.

Each member cluster keeps its own TLS, credentials, and `Host` header — see
[Providers and clusters](../providers-and-routing/providers-and-clusters/).
An end-to-end router test proves the isolation directly: after a failover
from a provider with a closed port to a live one, the live provider's
upstream request carries the live provider's API key and never the failed
primary's (`credential_isolation_across_failover` in
`crates/proxy-http/tests/router_aggregate.rs`).

## When a request moves to the next member

A member is tried once. The router advances to the next member in the list
only on an outcome the retry engine treats as certainly unserved: a
connection failure, a `refused-stream`, a reset before any response byte, or
a response with status 429, 500, 502, or 503
(`crates/proxy-simple-config/src/lower.rs`'s `lower_route`, which hardcodes
the route's `retry_on` to `connect-failure,refused-stream,reset,
retriable-status-codes` with that exact status list). See
[Timeouts and retries](../providers-and-routing/timeouts-and-retries/) for
the full trigger table — the same one applies here, since a fallback attempt
*is* a retry, just one that lands on a different member.

Once the client has started receiving a stream from a member, that response
is final. No later member is ever tried after the first response byte has
reached the client — a partially-streamed reply cannot be silently replaced
by a different provider's answer.

Member selection is strict order, not blended traffic: a member is skipped
only once it has actually been tried and failed in this request (or, on a
config-reload race, is momentarily missing from the cluster registry). This
is a deliberate divergence from the reference implementation's own aggregate
cluster, which can
bleed a fraction of traffic across a partially-healthy member boundary — for
LLM provider fallback that would mean a silent slice of traffic landing on
the fallback provider's own billing and rate limits while the primary is
only partially degraded, which nobody wants
(`crates/proxy-cluster/src/manager.rs`'s `ClusterHandle::select_aggregate_member`
doc comment). Nested aggregates are not supported: a fallback chain is one
level of failover, never a fallback of a fallback chain.

## `retries.attempts` and the fallback chain interact through one budget

`routes[].retries.attempts` (default `1`, max `5`) is not a separate budget
from failover — both draw on the same underlying retry count. Reaching the
last of *N* chain members needs at least *N*-1 retries, so lowering raises
the emitted retry count to whichever is larger: your configured `attempts`,
or the number needed to reach every fallback
(`crates/proxy-simple-config/src/lower.rs:903-910`). A three-member chain
(primary plus two fallbacks) with `retries: { attempts: 1 }` — not enough on
its own — still gets `num_retries: 2` in the lowered config, proven by
`num_retries_is_raised_to_reach_every_member` in
`crates/proxy-simple-config/tests/fallbacks.rs`.

The corollary is easy to miss: **`retries: { attempts: 0 }` does not disable
failover** when `fallbacks` is set. It only removes any *extra* retries
beyond what reaching the last fallback already requires — the `.max()` in the
formula above always wins in favor of finishing the chain. `attempts: 0`
disables retries outright only on a route with no `fallbacks` at all, where
there is no chain to protect.

One more consequence of sharing a single budget: once a route has any
`fallbacks`, `retries.attempts` no longer buys extra attempts against the
*same* primary provider. The very first failed attempt marks the primary as
tried for this request, so the next retry moves straight to the first
fallback rather than repeating the primary — same-provider retries stay
useful only on a route with no `fallbacks` configured.

## Same wire dialect only

Every provider in a chain must speak the same wire dialect as the primary.
An OpenAI-shaped provider falling back to another OpenAI-shaped provider
(including `openai-compatible`) is supported. A chain mixing OpenAI-shaped
and Anthropic-shaped providers is a **load error**, not a best-effort
attempt or a warning: the primary's request body would not be valid for the
fallback's API, and the fallback's response would be scanned for tokens by
the wrong dialect's parser — silently wrong billing numbers, not just a
broken request
(`cross_dialect_fallback_is_rejected` in
`crates/proxy-simple-config/tests/fallbacks.rs`). See
[Getting started](../getting-started/quickstart/) for the exact error text
this produces.

## The `models` catalogue has no fallback of its own

`models.<name>.providers` is an ordered list, but in this schema version only
`providers[0]` is ever used to serve traffic — there is no failover among a
model's listed providers the way `routes[].fallbacks` provides. See
[Providers and clusters](../providers-and-routing/providers-and-clusters/)
for what a `models` entry does support.

## Bootstrap configuration

The same mechanism is available directly: define an
`envoy.clusters.aggregate` cluster with `lb_policy: CLUSTER_PROVIDED` and a
`cluster_type.typed_config.clusters` member list, then point a route's
`cluster` at it. The same-dialect restriction above is specific to this
configuration format's usage-metering filter — a raw bootstrap configuration
has no such check, since it has no concept of a wire dialect to protect.
