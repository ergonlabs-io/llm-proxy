---
title: Reload configuration
description: "Apply config changes with SIGHUP, and see which settings a reload applies and which need a restart."
summary: SIGHUP re-reads the config file a running proxy booted with and
  publishes a new snapshot. A config that fails to parse or validate leaves
  the proxy serving the previous snapshot and logs the full error.
lastUpdated: 2026-10-18
related:
  - configuration/configuration-file
  - observability/metrics-and-stats
  - operations/draining-and-shutdown
---

# Reload configuration

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

Some settings need a restart, and some changes make the proxy refuse the
whole reload. See [What a reload applies](#what-a-reload-applies) for the
full list.

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

## What a reload applies

A reload parses the whole file again, so every file the config names (such as
`api_key_file` or `price_list_file`) is read again. Being read again does not
always mean the new value is used. This table says what is active for requests
that start after a successful reload.

| Setting | After `SIGHUP` | Restart needed |
|---|---|---|
| `routes`, `models`, `limits` rules | Active for new requests. | No |
| `providers.*` (`base_url`, `api_key`, `api_key_file`, other fields) | Active. Upstream keep-alive connections from before the reload close, so a rotated provider key is not sent again. | No |
| `${ENV}` values | Read again from the environment of the running process, which does not change. | Yes, to change the value |
| `listen.tls` `cert_file` / `key_file` | Read again on the next accepted connection. New connections get the new certificate. A file that cannot be read makes the listener reset every new TLS connection until a later reload succeeds. | No |
| Listener admission limits | Active from the next accepted connection. | No |
| `pricing` | Installed if the chain has no auth store. With an `auth:` block, the stored card wins; use `PUT /pricing`. | No |
| `auth.max_policy_staleness` | Active. | No |
| `auth.keys` (add, remove, `revoked: true`) | **Not applied.** The proxy keeps the key list it started with. A removed or revoked configured key still authenticates. | Yes |
| `auth.hmac_secret` / `auth.hmac_secret_file` | **Do not change and reload.** See the warning below. | Yes |
| `auth.store`, `auth.tenant_credentials` | Not applied. | Yes |
| `observability.tracing`, `observability.metrics` | Not applied. The OTLP exporters keep the settings from startup. No warning is logged. | Yes |
| `ledger`, `observability.traces` | A change makes the proxy refuse the whole reload and keep the previous snapshot. | Yes |
| Keys, tenants and policy from the admin API | Not part of the file. They stay in the auth store and are not changed by a reload. | No |

> **Warning: rotate the HMAC secret with a restart.** After a reload that
> changes the secret, the proxy verifies presented keys with the new secret
> but keeps the old key digests, and it mints new keys with the old secret.
> Every virtual key, including one minted after the reload, is refused with
> `401`, and the log still says the reload succeeded. A restart applies the
> new secret to both sides. This is a known defect.

To revoke a key without a restart, use the admin API: `DELETE /keys/{id}` for
a key minted through the API, or `DELETE /tenants/{id}` to revoke every key
of a tenant, configured keys included. See
[Virtual keys](../../authentication/virtual-keys/#managing-keys-and-tenants-at-runtime).

### Requests in flight

A request that started before the reload finishes on the configuration it
started with, including its retries and fallbacks. A downstream HTTP
connection from before the reload closes gracefully after its current
request: an idle keep-alive closes, and the next request opens a new
connection that uses the new configuration. A TCP proxy connection is not
closed.

### Errors that a reload does not catch

A reload checks that the file parses and validates. Some errors appear only
when a worker builds the new listener, after the reload has logged success:

- A provider cluster that fails to build is left out of the cluster set and
  logged at `error`.
- A TLS file that cannot be read, or a filter that fails to build, makes the
  listener reset new connections until a later reload succeeds.

Run `--mode validate` before you send `SIGHUP`, and check the log after it.

The admin server's `/config_dump` and `/clusters` endpoints reflect a reload.
The admin server and the workers register their snapshot handles with one
registry, and a reload publishes into every handle in it. The end-to-end test
`sighup_reload_is_reflected_in_config_dump_and_clusters` in
`crates/proxy/tests/reload.rs` renames a cluster, sends `SIGHUP`, and checks
that both endpoints show the new name. The unit test
`start_admin_registers_its_handle_into_the_shared_registry` in
`crates/proxy/src/main.rs` checks that a snapshot published through the shared
registry reaches `/config_dump`.

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
