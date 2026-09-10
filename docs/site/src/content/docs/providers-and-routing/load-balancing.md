---
title: Load balancing
summary: Which `lb_policy` values a cluster can actually run, why two are
  rejected at load time rather than approximated, and why load balancing has
  nothing to choose between in the plain configuration format.
last_updated: 2026-08-26
related:
  - ../providers-and-routing/providers-and-clusters/
  - ../providers-and-routing/failover-and-aggregates/
  - ../configuration/configuration-file/
---

# Load balancing

Load balancing picks a host among a cluster's endpoints. This page is about
the engine's `lb_policy` support in general — see
[Providers and clusters](../providers-and-routing/providers-and-clusters/)
first if you have not read it, because it changes what this page even means
for this configuration format.

## In this configuration format, there is nothing to balance

Every `providers.<name>` entry lowers to a cluster with exactly one endpoint
— the host and port parsed from `base_url`. Lowering hardcodes that
cluster's `lb_policy` to `ROUND_ROBIN`
(`crates/proxy-simple-config/src/lower.rs`'s `lower_provider`), but with one
host, round robin (or any other policy) always returns the same host. There
is no field in this schema version to give one provider a second endpoint,
so a policy choice here has no observable effect. Real load balancing across
more than one endpoint is only reachable through a bootstrap configuration,
covered below.

## What a cluster's `lb_policy` actually does (bootstrap configuration)

| `lb_policy` | Status | Notes |
|---|---|---|
| `ROUND_ROBIN` | Implemented | A plain rotating cursor when every candidate host has equal weight; smooth weighted round robin (nginx's algorithm) when weights differ, so a 5:1 weight split interleaves as `A A A B A A`, not batched as `A A A A A B`. |
| `LEAST_REQUEST` | Implemented | Power-of-two-choices: draws `choice_count` candidates (2 by default) uniformly and picks whichever has fewer active requests. Degrades to uniform random once every host reads zero active requests, which is correct for "no signal yet", not a bug. |
| `RANDOM` | Implemented | Uniform pick over the candidate set. |
| `RING_HASH` | **Rejected at load** | Session affinity only holds if every proxy in a fleet hashes identically; that bit-exact parity is unproven here, and there is no differential test harness yet to prove it. Configuring it is a load error naming the policy, not a silent substitution of another one. |
| `MAGLEV` | **Rejected at load** | Same reason as `RING_HASH`: no bit-exact parity, no differential harness, rejected rather than approximated. |
| `CLUSTER_PROVIDED` | Reserved | Only legal on an `envoy.clusters.aggregate` cluster — see [Failover and aggregates](../providers-and-routing/failover-and-aggregates/). Required there (an aggregate has no hosts of its own to run a policy over) and rejected everywhere else, since there is no other cluster-provided host-picking implemented. |

Rejection happens at config load, with the policy named in the error, both
for a raw bootstrap configuration's `lb_policy` field and for the equivalent check
`proxy-cluster` runs at cluster-build time
(`crates/proxy-config/src/lower.rs`'s `convert_cluster`;
`ring_hash_is_rejected_at_build_time` and `maglev_is_rejected_at_build_time`
in `crates/proxy-cluster/src/load_balancer.rs`). Ground rule #1 in this
project's engineering notes forbids silently substituting one policy for
another, so a config asking for session affinity that cannot be honored
fails loudly instead of serving traffic under a policy that quietly breaks
that affinity.

## What every policy shares: priority spillover and the panic threshold

Two behaviors sit above the policy choice and apply identically regardless
of which of the three implemented policies a cluster runs
(`crates/proxy-cluster/src/load_balancer.rs`'s `HostPicker`):

- **Priority spillover.** Traffic prefers priority 0 hosts and only spills to
  priority 1 as priority 0's healthy fraction drops, using a 1.4x
  overprovisioning factor: at 50% of priority 0 healthy, priority 0 still
  gets `min(100, 50 × 1.4) = 70%` of traffic, and the remaining 30% spills to
  priority 1 — verified at exactly that 70/30 split over 100,000 picks by
  `half_healthy_priority_zero_spills_thirty_percent_to_priority_one`.
- **Healthy-panic threshold.** If fewer than 50% of the hosts at the selected
  priority are healthy, selection widens to every host at that priority
  (healthy and unhealthy) rather than narrowing to an ever-smaller healthy
  set that would concentrate load dangerously. Exactly 50% healthy does
  **not** panic — the check is strictly less than 50%
  (`panic_threshold_boundary_exactly_50_percent_does_not_panic`).

Both need more than one endpoint and, for priority spillover, more than one
priority to have any visible effect — reachable in a bootstrap configuration,
not in this configuration format's single-endpoint clusters.

## Health and circuit breakers are part of "which host", too

This configuration format has no field for active health checking or for
tuning circuit-breaker budgets — a cluster it builds always uses the same
fixed default thresholds (1024 connections, 1024 pending requests, 1024
concurrent requests, 3 concurrent retries) and never probes a host's health
on its own. A host only ever looks unhealthy to the picker above through
active health-check fields written directly into a bootstrap configuration,
which this page does not cover further.

Of the four circuit-breaker budgets, only two are wired to a real call site
today: `max_requests` (acquired per request, held for the full response
stream — LLM streaming keeps a request "active" far longer than
time-to-headers) and `max_connections`, enforced at the dial itself so an
over-budget cluster never opens the socket
(`crates/proxy-cluster/src/pool.rs`'s `ConnectPool::new_stream`, proven by
`max_connections_is_enforced_at_dial_and_released_on_drop`). Either budget
being exhausted produces the same outcome: `503`, the `UO` response flag, and
an `x-envoy-overloaded: true` response header
(`max_requests_zero_records_and_renders_the_uo_flag` in
`crates/proxy-http/tests/response_flags.rs`). `max_pending_requests` is a
bounded parking queue in front of `max_connections`: when all connection
slots are held, a caller parks only if it can acquire a pending slot; a full
pending queue produces the same immediate overload response. `max_retries`
is parsed and recorded but has no enforcement call site yet.

## Bootstrap configuration: a worked weighted example

```yaml
clusters:
  - name: provider:openai-pool
    type: STRICT_DNS
    lb_policy: LEAST_REQUEST
    load_assignment:
      cluster_name: provider:openai-pool
      endpoints:
        - lb_endpoints:
            - endpoint:
                address: { socket_address: { address: api.openai.com, port_value: 443 } }
              load_balancing_weight: 1
            - endpoint:
                address: { socket_address: { address: openai-proxy.internal, port_value: 443 } }
              load_balancing_weight: 1
```

Both endpoints are priority 0 by default (the `priority` field on the
`endpoints` entry, omitted here) and equal weight, so `LEAST_REQUEST` picks
between them by active request count rather than a fixed split. This shape —
more than one endpoint per cluster, an explicit `lb_policy` with real
candidates to choose from — is not expressible in the plain configuration
format at all; see
[Providers and clusters](../providers-and-routing/providers-and-clusters/)
for why.
