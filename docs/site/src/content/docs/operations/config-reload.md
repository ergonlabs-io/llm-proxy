---
title: Config reload
summary: SIGHUP re-reads the config file a running proxy booted with and
  publishes a new snapshot. A config that fails to parse or validate leaves
  the proxy serving the previous snapshot and logs the full error.
last_updated: 2026-10-17
related:
  - ../configuration/configuration-file/
  - ../observability/metrics-and-stats/
  - ../operations/draining-and-shutdown/
---

# Config reload

llm-proxy re-reads its config on `SIGHUP`. There is no file-system watcher —
nothing reloads automatically when the file changes on disk — so a reload
only happens when something sends the signal:

```sh
kill -HUP <pid>
```

## Reload restrictions

A bootstrap with `dynamic_resources` ignores `SIGHUP` and logs a warning.
Apply dynamic changes through its configured xDS source. The proxy also
ignores reload signals while draining or shutting down.

Some settings require a restart:

- The auth control-plane store and policy poll interval are fixed at startup.
- Changing `ledger` or `observability.traces` rejects the entire reload and
  retains the previous snapshot. Their writers and destinations are opened
  at startup.

Validate the edited file before signalling the running process:

```sh
llm-proxy --config llmproxy.yaml --mode validate
```

For a shared store, include the replica's `--service-node` flag when validating.
For an Envoy bootstrap, use `-c bootstrap.yaml` instead of `--config`.

## The safety property comes first

A config that fails to parse or fails validation **never** takes the process
down and **never** partially applies. The proxy keeps serving the exact
snapshot it had a moment before, and the failure is logged at `error` with
the same full dotted field path a boot-time failure would show:

```text
SIGHUP: config reload failed; continuing to serve the previous snapshot
```

This is proven by
`sighup_with_a_broken_config_keeps_serving_and_logs_error` in
`crates/proxy/tests/reload.rs`, which rewrites the config file to invalid
YAML, sends `SIGHUP`, and then checks — repeatedly, over a settle window,
not once — that the process is still alive and the original listener is
still accepting connections.

## What a successful reload does

A reload re-reads and re-parses the exact same config file the process
booted with, then applies the result in this order
(`crates/proxy/src/main.rs`'s `reload` function):

1. Resolve stats handles for any cluster the new snapshot names that the
   running process has never seen before, so traffic to a brand-new cluster
   is counted in `/stats` from its first request — see
   [Metrics and /stats](../../observability/metrics-and-stats/).
2. Update the shared cluster manager with the new cluster set. A cluster
   that fails to build (an unimplemented load-balancing policy, a bad TLS
   config) is logged at `error` and left out of the live cluster set —
   unlike at boot, where the same failure is fatal, a reload cannot take
   the process down for it.
3. Publish the new snapshot. Every worker's listener manager reconciles
   against it, so listeners are added, removed, or reconfigured to match.

Each successful reload advances an internal version counter by exactly one,
logged in the success line:

```text
SIGHUP: config reload succeeded
```

An **unchanged** config file still reloads successfully and still advances
the version — a `SIGHUP` after an operator re-saves the file without
changing anything is harmless, not a no-op that skips logging
(`sighup_with_an_unchanged_config_is_harmless`,
`snapshot_version_advances_across_reloads` in
`crates/proxy/tests/reload.rs`).

## What picks up a reload, and what does not

Listeners and clusters both reconcile against the new snapshot — a route
added, a provider's `base_url` changed, or a whole new listener all take
effect. A provider's `api_key_file` or `auth.hmac_secret_file` is also
re-read from disk on a reload, since the whole config file is re-parsed
from scratch — this is the practical way to rotate a file-based secret
without a restart, even though nothing watches the file automatically.

The admin server's `/config_dump` and `/clusters` endpoints reflect a reload.
The admin server and the workers register their snapshot handles with one
registry, and a reload publishes into every handle in it. The end-to-end test
`sighup_reload_is_reflected_in_config_dump_and_clusters` in
`crates/proxy/tests/reload.rs` renames a cluster, sends `SIGHUP`, and checks
that both endpoints show the new name. The unit test
`start_admin_registers_its_handle_into_the_shared_registry` in
`crates/proxy/src/main.rs` checks that a snapshot published through the shared
registry reaches `/config_dump`. Before this fix both endpoints served the boot
snapshot after a reload.

These items also change on a reload:

- **Stats series.** A reload hides the series of a cluster or listener that the
  new config no longer names. After two consecutive configs omit the name, the
  proxy frees the series slot. A name that returns later starts at zero. See
  [Metrics and /stats](../../observability/metrics-and-stats/#series-lifetime-and-reload).
- **Rate card (`pricing`).** Without a control-plane store, a reload installs a
  changed `pricing`. A reload with an unchanged `pricing` keeps a card that
  `PUT /pricing` installed. With a store, a reload never replaces the stored
  card. Tests: `without_a_store_a_changed_configured_card_is_installed_on_reload`,
  `without_a_store_a_reload_that_did_not_change_the_card_keeps_a_put_card`, and
  `with_a_store_a_reload_never_replaces_the_stored_card` in
  `crates/proxy-filters/src/usage_filter/rate_card_tests.rs`.
- **Global connection limit.** The accept loop reads the limit and the
  listener's `ignore_global_conn_limit` from the current snapshot on each
  accepted connection. A reload applies to the next connection
  (`crates/proxy-core/src/listener.rs:854-858`).
- **Tenant-budget cutover.** `PUT /tenants/{id}/budget` returns `409` while the
  serving spend filter lacks `legacy_tenant_budget_cutover`. Each build of the
  filter records the value, so a reload that adds the field lifts the `409`
  (`crates/proxy-filters/src/spend_limit_filter.rs:511-516`). See
  [Spend policies](../../limits-and-budgets/spend-policies/#migrating-tenant-budgets).

## SIGTERM after a reload

A `SIGHUP` reload does not disturb the shutdown/drain sequence: a `SIGTERM`
sent after one or more reloads still drains and exits cleanly, proven by
`sigterm_after_a_reload_still_drains_and_exits_cleanly` in
`crates/proxy/tests/reload.rs`. See
[Draining and shutdown](../../operations/draining-and-shutdown/) for what that
sequence does.
