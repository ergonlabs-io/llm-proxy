---
title: Load balancing
description: "How a cluster picks one of its endpoints, and how a models alias spreads requests across its providers. A dialect provider has one endpoint; balancing across endpoints needs an Envoy bootstrap."
summary: Which `lb_policy` values a cluster can run, why two are
  rejected at load time rather than approximated, and why a provider in the
  plain configuration format has no endpoint to choose between. It also
  points to weights, which balance across the providers of a `models` alias.
lastUpdated: 2026-10-20
related:
  - providers-and-routing/providers-and-clusters
  - providers-and-routing/failover-and-aggregates
  - configuration/configuration-file
---

# Load balancing

Load balancing picks one host among a cluster's endpoints. Use it when one
cluster has several endpoints and you want to spread requests across them.

To enable it, write a cluster with several endpoints and an `lb_policy` in an
Envoy bootstrap configuration. The `llmproxy` dialect gives each provider
exactly one endpoint, so it has no setting for balancing across endpoints.
To spread requests across the providers of a `models` alias, use `weight`.
See [Balancing across the providers of a model](#balancing-across-the-providers-of-a-model).
For the reason for the endpoint rule, see
[Providers and clusters](../../providers-and-routing/providers-and-clusters/).
The
[worked example](#bootstrap-configuration-a-worked-weighted-example) at the
end of this page shows the Envoy form.

## Balancing across the providers of a model

A `models.<name>.providers` list can pick its first provider in proportion
to a `weight` on each entry. This balances across providers. It does not
balance across the endpoints of one provider. The `lb_policy` table below
does not apply to it.

```yaml
models:
  chat-default:
    providers:
      - { provider: openai, weight: 3 }
      - { provider: together, weight: 1 }
```

The proxy draws the first provider once for each request. The draw is
uniform and random, and it keeps no per-worker state. The split is the same
on every worker. Replicas do not coordinate. The split matches the weights
over many requests, not over a few. Weight `0` makes an entry a fallback
only. A provider ejected by its `outlier_detection` gets no first picks
until the ejection ends. The next entry in list order that is not ejected
takes its share. The proxy does not support cost-aware selection.

For the rules for `weight`, the load errors, the fallback chain, and
`outlier_detection`, see
[Failover and aggregates](../../providers-and-routing/failover-and-aggregates/#weighted-selection-in-the-models-catalogue).

## Inside a provider, there is nothing to balance

Every `providers.<name>` entry lowers to a cluster with exactly one endpoint
— the host and port parsed from `base_url`. Lowering hardcodes that
cluster's `lb_policy` to `ROUND_ROBIN`, but with one
host, round robin (or any other policy) always returns the same host. There
is no field in this schema version to give one provider a second endpoint,
so a policy choice here has no observable effect. Real load balancing across
more than one endpoint is only reachable through a bootstrap configuration,
covered below.

## What a cluster's `lb_policy` does (bootstrap configuration)

| `lb_policy` | Status | Notes |
|---|---|---|
| `ROUND_ROBIN` | Implemented | A plain rotating cursor when every candidate host has equal weight; smooth weighted round robin (nginx's algorithm) when weights differ, so a 5:1 weight split interleaves as `A A A B A A`, not batched as `A A A A A B`. |
| `LEAST_REQUEST` | Implemented | Power-of-two-choices: draws `choice_count` candidates (2 by default) uniformly and picks whichever has fewer active requests. See "What `LEAST_REQUEST` counts" below. When every host has the same count, including when all are idle, the pick is uniform random. |
| `RANDOM` | Implemented | Uniform pick over the candidate set. |
| `RING_HASH` | **Rejected at load** | Session affinity only holds if every proxy in a fleet hashes identically. The proxy does not guarantee that bit-exact parity with Envoy, so it rejects the policy. Configuring it is a load error that names the policy. The proxy never substitutes another policy. |
| `MAGLEV` | **Rejected at load** | Same reason as `RING_HASH`: the proxy rejects the policy and does not approximate it. |
| `CLUSTER_PROVIDED` | Reserved | Only legal on an `envoy.clusters.aggregate` cluster — see [Failover and aggregates](../../providers-and-routing/failover-and-aggregates/). Required there (an aggregate has no hosts of its own to run a policy over) and rejected everywhere else, since there is no other cluster-provided host-picking implemented. |

Rejection happens at config load, with the policy named in the error. The
cluster build makes the same check. The strict-config rule forbids silent
substitution of one policy for another. A config that asks for session
affinity that the proxy cannot honor fails at load. It does not serve traffic
under a policy that breaks that affinity.

## What `LEAST_REQUEST` counts

Each host has a count of active requests. The router adds 1 to the count when
it starts an attempt against the host. It subtracts 1 when the attempt ends.
An attempt ends in one of three ways:

- The response body reaches its end.
- The client drops the response before the end.
- For an upgraded connection (WebSocket), the tunnel closes.

A retry or a fallback is a new attempt. It counts against the host that it
uses. An attempt that fails before a response leaves no count. When the router
hedges a request, each host that it tries counts once. A declined upgrade
holds its count until its response body ends.

The count belongs to the host, not to a snapshot of the cluster. A health
check, an outlier ejection, or a DNS or EDS refresh rebuilds the host
snapshot. The new snapshot for the same address shares the old counter, so
in-flight requests keep their count and decrement the right counter. A new
address starts at 0. A request counts from the moment the attempt starts, so
a long SSE stream keeps its host loaded until the stream ends.

## What every policy shares: priority spillover and the panic threshold

Two behaviors sit above the policy choice and apply identically regardless
of which of the three implemented policies a cluster runs:

- **Priority spillover.** Traffic prefers priority 0 hosts and only spills to
  priority 1 as priority 0's healthy fraction drops, using a 1.4x
  overprovisioning factor: at 50% of priority 0 healthy, priority 0 still
  gets `min(100, 50 × 1.4) = 70%` of traffic, and the remaining 30% spills to
  priority 1.
- **Healthy-panic threshold.** If fewer than 50% of the hosts at the selected
  priority are healthy, selection widens to every host at that priority
  (healthy and unhealthy) rather than narrowing to an ever-smaller healthy
  set that would concentrate load dangerously. Exactly 50% healthy does
  **not** panic — the check is strictly less than 50%.

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

All four circuit-breaker budgets have an enforcement call site. This list
gives the semantics of each:

- `max_requests` is acquired per request and held for the full response stream.
  LLM streaming keeps a request "active" far longer than time-to-headers.
- `max_connections` counts the open upstream sockets of one cluster, across
  every worker and every host. The dial claims a slot before it opens the
  socket, so an over-budget cluster never opens it. An idle pooled
  connection holds its slot. The slot returns when the socket closes, not when
  the cache entry goes. The sweep, the peer, and the removal of an endpoint all
  close sockets. See
  [How a pooled connection ends](../../providers-and-routing/providers-and-clusters/#how-a-pooled-connection-ends).
- `max_pending_requests` is a bounded parking queue in front of
  `max_connections`. When all connection slots are held, a caller parks only if
  it can acquire a pending slot. A full pending queue produces the same
  immediate overload response.
- `max_retries` limits the retries in flight at one time. The router asks for a
  retry slot before each retry. A request that cannot get one stops retrying
  and the access log shows the `URX` flag.

An exhausted `max_requests`, `max_connections`, or `max_pending_requests`
budget produces the same outcome: `503`, the `UO` response flag, and an
`x-envoy-overloaded: true` response header.

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
[Providers and clusters](../../providers-and-routing/providers-and-clusters/)
for why.

## Implementation notes

This section is for maintainers.

- Dialect lowering sets `ROUND_ROBIN`: `lower_provider` in
  `crates/proxy-simple-config/src/lower.rs`. Load-time rejection of
  `RING_HASH` and `MAGLEV`: `convert_cluster` in
  `crates/proxy-config/src/lower.rs`. Build-time tests:
  `ring_hash_is_rejected_at_build_time` and
  `maglev_is_rejected_at_build_time` in
  `crates/proxy-cluster/src/load_balancer.rs`.
- Weighted selection across the providers of a `models` alias: `lower_model`
  and `check_model_weights` in `crates/proxy-simple-config/`, with the tests
  listed in
  [Failover and aggregates](../../providers-and-routing/failover-and-aggregates/#implementation-notes).
  The weighted route uses Envoy `weighted_clusters`, not `lb_policy`.
- Spillover and panic threshold: `HostPicker` in the same file. Tests:
  `half_healthy_priority_zero_spills_thirty_percent_to_priority_one` (70/30
  split over 100,000 picks) and
  `panic_threshold_boundary_exactly_50_percent_does_not_panic`.
- `LEAST_REQUEST` count: `Host::begin_request` and `ActiveRequestGuard` in
  `crates/proxy-cluster/src/lib.rs`, and the attempt guard in
  `crates/proxy-http/src/router.rs`. Tests in
  `crates/proxy-http/tests/router_least_request.rs`:
  `streaming_requests_are_counted_and_spread_by_least_request`,
  `downstream_dropping_a_streaming_response_releases_the_count`,
  `a_failed_attempt_leaves_no_count_and_the_retry_is_counted`,
  `an_accepted_upgrade_holds_the_count_for_the_tunnel_lifetime`,
  `a_declined_upgrade_holds_the_count_until_the_response_body_ends`, and
  `a_hedge_counts_each_attempted_host_once_and_releases_both`. Counter
  sharing across snapshot rebuilds, in `crates/proxy-cluster`:
  `health_transition_rebuild_shares_the_in_flight_counter`,
  `ejection_rebuild_shares_the_in_flight_counter`, and
  `carry_over_shares_the_in_flight_counter_with_the_old_snapshot`.
- Circuit breakers: `ConnectPool::new_stream` in
  `crates/proxy-cluster/src/pool.rs` (test
  `max_connections_is_enforced_at_dial_and_released_on_drop`);
  `sleep_backoff_and_reserve_retry` in `crates/proxy-http/src/router.rs`
  (test `retry_limit_exceeded_renders_the_urx_response_flag`);
  `max_requests_zero_records_and_renders_the_uo_flag` in
  `crates/proxy-http/tests/response_flags.rs`.
