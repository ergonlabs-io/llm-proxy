---
title: Reload configuration
description: "Apply config changes with SIGHUP, and see which settings a reload applies and which need a restart."
summary: SIGHUP re-reads the config file a running proxy booted with and
  publishes a new snapshot. A config that fails to parse or validate leaves
  the proxy serving the previous snapshot and logs the full error.
lastUpdated: 2026-11-09
related:
  - configuration/configuration-file
  - authentication/virtual-keys
  - limits-and-budgets/spend-policies
  - administration/admin-api
  - observability/metrics-and-stats
  - operations/draining-and-shutdown
---

Use a reload to change routes, models, limits, and provider settings without
a restart. To reload, edit the config file and send `SIGHUP` to the process:

```sh
kill -HUP <pid>
```

llm-proxy has no file-system watcher. A reload happens only when something
sends the signal. Some settings need a restart. The table in
[What a reload applies](#what-a-reload-applies) lists them.

## At a glance

- **Default when unset:** nothing reloads. The proxy has no file watcher. A
  reload happens only on `SIGHUP`.
- **Failure mode:** a reload that fails to load, or that changes a setting
  fixed at start, is refused whole. The proxy keeps serving the previous
  config.

## Reload restrictions

The proxy ignores `SIGHUP` while it drains or shuts down. It logs
`SIGHUP ignored: the proxy is draining and will not bind new listeners` or
`SIGHUP ignored: the proxy is shutting down and will not reload`.

Some changes make the proxy refuse the whole reload. See
[What a reload applies](#what-a-reload-applies) for the full list.

Validate the edited file before signalling the running process:

```sh
llm-proxy --config llmproxy.yaml --mode validate
```

For a shared store, include the replica's `--service-node` flag when validating.

## A failed reload keeps the previous config

A config that fails to parse or fails validation does not stop the process and
does not apply in part. The proxy keeps serving the snapshot it had before.
It logs the failure at `error` with the same full dotted field path that a
boot-time failure shows:

```text
SIGHUP: config reload failed; continuing to serve the previous snapshot
```

## What a successful reload does

A reload re-reads the same config file that the process started with. Then it
applies the result in this order:

1. Resolve stats handles for any provider that the new config names and the
   running process has never seen. Traffic to a new provider is counted in
   `/stats` from its first request. See
   [Metrics and /stats](/docs/llm-proxy/observability/metrics-and-stats/).
2. Update the provider set. A provider that fails to build (for example, a
   bad TLS config) is logged at `error` and left out of the live set. At
   boot the same failure is fatal. A reload cannot take the process down for
   it.
3. Publish the new snapshot. Every worker's listener manager reconciles
   against it, so listeners are added, removed, or reconfigured to match.

Each successful reload advances an internal version counter by one. The
success line shows it:

```text
SIGHUP: config reload succeeded
```

An unchanged config file also reloads successfully and advances the version.
A `SIGHUP` after you save the file without changes is harmless.

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
| `admin` address (`admin` or `admin.address`; add, remove, change) | A change makes the proxy refuse the whole reload. The admin server stays on the address from startup. | Yes |
| `admin.tls` (add, remove, `cert_file` / `key_file`) | Read again on the next accepted admin connection, the same as `listen.tls`. A file that cannot be read makes the admin port close every new connection until a later reload succeeds. Removing `admin.tls` serves plain HTTP. | No |
| `pricing` | Installed if the chain has no auth store. With an `auth:` block, the stored card wins; use `PUT /pricing`. | No |
| `auth.max_policy_staleness` | Active. | No |
| `auth.declared_policy` (add, remove, change) | Active. A change starts a background reconcile after the new config is published. See [Declare tenant policy in the config file](#declare-tenant-policy-in-the-config-file). | No |
| `auth.keys` (add, remove, `revoked: true`) | A change makes the proxy refuse the whole reload. A removed or revoked configured key keeps authenticating until a restart. | Yes |
| `auth.hmac_secret` / `auth.hmac_secret_file` | A changed secret makes the proxy refuse the whole reload. Keys keep working with the secret from startup. | Yes |
| `auth.store`, `auth.tenant_credentials` | A change makes the proxy refuse the whole reload. A rotated key file at the same path is a change. | Yes |
| `auth.spend.recovery_journal_path` | A change makes the proxy refuse the whole reload. This includes adding or removing the field. The proxy keeps the journal from startup. | Yes |
| `observability.tracing`, `observability.metrics` | A change makes the proxy refuse the whole reload. | Yes |
| `ledger`, `observability.traces` | A change makes the proxy refuse the whole reload. | Yes |
| Command-line flags (such as `--service-node`) | Not part of the file. They are fixed when the process starts. | Yes |
| Keys, tenants and policy from the admin API | Not part of the file. They stay in the auth store and are not changed by a reload. | No |

A refused reload keeps the previous snapshot and logs this line at `error`:

```text
SIGHUP: config reload refused; continuing to serve the previous snapshot
```

Its `detail` field names the field that changed and says to restart. The
auth and spend fields appear under their internal names, for example
`typed_config.hmac_secret (the dialect's `auth.hmac_secret` /
`auth.hmac_secret_file`)` or `typed_config.recovery_journal_path (the
dialect's `auth.spend.recovery_journal_path`)`. For `ledger`, `observability.traces`,
`observability.tracing`, `observability.metrics`, and the `admin` address, the
log line names the field in parentheses. For the `admin` address, the `running`
and `reloaded` fields show both addresses. The log never contains the secret.

To rotate the HMAC secret, change it and restart. Configured keys must be
digested again under the new secret, and keys minted through the admin API stop working, because their digests were
made with the old secret.

To revoke a key without a restart, use the admin API: `DELETE /keys/{id}` for
a key minted through the API, or `DELETE /tenants/{id}` to revoke every key
of a tenant, configured keys included. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/#managing-keys-and-tenants-at-runtime).

### Requests in flight

A request that started before the reload finishes on the configuration it
started with, including its retries and fallbacks. A downstream HTTP
connection from before the reload closes gracefully after its current
request: an idle keep-alive closes, and the next request opens a new
connection that uses the new configuration.

### Errors that a reload does not catch

A reload checks that the file parses and validates. Some errors appear only
when a worker builds the new listener, after the reload has logged success:

- A provider that fails to build is left out of the live set and logged at
  `error` as `SIGHUP: cluster rejected during reload`.
- A TLS file that cannot be read, or a filter that fails to build, makes the
  listener reset new connections until a later reload succeeds. The
  `llmproxy.auth` filter is the exception: its config is parsed before the
  reload is applied, so an `auth` error (such as an unreadable
  `auth.hmac_secret_file`) refuses the reload instead.

Run `--mode validate` before you send `SIGHUP`, and check the log after it.

The admin server's `/config_dump` and `/clusters` endpoints show the config
after a reload.

These items also change on a reload:

- **Stats series.** A reload hides the series of a provider or listener that the
  new config no longer names. After two consecutive configs omit the name, the
  proxy frees the series slot. A name that returns later starts at zero. See
  [Metrics and /stats](/docs/llm-proxy/observability/metrics-and-stats/#series-lifetime-and-reload).
- **Rate card (`pricing`).** Without a control-plane store, a reload installs a
  changed `pricing`. A reload with an unchanged `pricing` keeps a card that
  `PUT /pricing` installed. With a store, a reload never replaces the stored
  card.
- **Global connection limit.** The accept loop reads `listen.max_connections`
  from the current snapshot on each accepted connection. A reload applies to
  the next connection.

## Declare tenant policy in the config file

Use `auth.declared_policy` to keep the model policy, budget, scoped budgets,
and limits of a tenant in the config file. The proxy writes these values to
the auth store at start and after a reload. Each block has the body of the
matching admin call: `PUT /tenants/{id}/policy`, `/budget`,
`/scoped_budgets`, and `/limits`.

Keys are not declared. Mint them with `POST /keys`, or list them in
`auth.keys`.

### Declare a tenant

1. Add `auth.declared_policy` to the config file. Set `revision` to 1.
2. Quote every `max_usd` value. An unquoted YAML number with a fraction is a
   load error.
3. Name only `providers` entries of the config file in `providers`.
4. Run `llm-proxy --config llmproxy.yaml --mode validate`.
5. Start the proxy, or send `SIGHUP`.
6. Raise `revision` on every later edit.

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
auth:
  hmac_secret_file: ./auth-secret
  store:
    persistent:
      path: ./auth-store.redb
  declared_policy:
    revision: 1
    tenants:
      - id: acme
        policy:
          access:
            only: ["gpt-4o-mini", "claude-*"]
          deny: ["claude-opus-*"]
        budget:
          max_usd: "500.00"
          period: monthly
        scoped_budgets:
          - name: openai-daily
            max_usd: "20"
            period: daily
            providers: [openai]
            alert_at_percent: [80, 100]
        limits:
          requests_per_minute: 600
          concurrent_streams: 20
```

Expected output of the validate command: `configuration 'llmproxy.yaml' OK`.
The `warning:` lines before it are normal. The `pricing` warning means that a
budget never fires until you set a rate card.

Set `auth.store` to `persistent` or `shared`. With `in_memory`, the proxy
writes the block again at each start, and admin writes are lost at restart.

In Envoy mode, set `declared_policy` (field 11) in the `typed_config` of
`llmproxy.auth`. The members are the same, with these differences:

- `policy.access` is `all: {}` or `only: {patterns: [...]}`, and `deny` is
  next to it in `policy`.
- A scoped budget `providers` entry is a cluster name. The dialect lowers the
  provider `openai` to the cluster `provider:openai`.
- The proxy checks the cluster names across resources. An unknown name is
  a load error, or a NACK for xDS.
- A tenant budget needs `legacy_tenant_budget_cutover` on
  `llmproxy.spend_limit`. Without it, the spend filter refuses to start on a
  stored tenant budget. The dialect sets it for you.

See the [field reference](/docs/llm-proxy/configuration/reference/#declaredpolicy)
for the types and limits.

### When the proxy writes the block

- At start, the proxy writes the block to the store before it serves. If the
  store cannot take the block, the start fails.
- On `SIGHUP` or an xDS update that changes the block, the write runs in the
  background after the new config is published. Request workers never wait
  for it.
- If a write fails, the policy poller retries it.
- If the block is unchanged, the proxy does not write it again. A change of
  `revision` alone is a change.
- If you remove the whole block, the proxy leaves the stored rows as they
  are. To remove every row that the file wrote, declare `tenants: []` with a
  higher `revision`.
- The proxy logs `declared tenant policy reconciled` with the `revision`,
  `written`, `deleted`, and `shadowed` counts.

### Who owns a row

Each stored row records its source. The file creates, updates, and deletes
only the rows it wrote. A block that you leave out of a tenant entry declares
no row, so the file removes a row of that kind that it wrote earlier.

An admin write to a declared row makes the row admin-owned. The file then
leaves the row alone. Each reconcile logs one warning for each such row. The
warning names the row, for example `auth.declared_policy.tenants[acme].policy`,
and tells you to use `DELETE /tenants/{id}/override`. Rows that the store
held before this feature count as admin-owned.

To give a tenant back to the file, call `DELETE /tenants/{id}/override`. See
[Declared tenant policy](/docs/llm-proxy/administration/admin-api/#declared-tenant-policy).

An admin clear or delete of a declared row is allowed. It logs a warning, and
the next reconcile writes the file value back. The proxy has no tombstones.
To remove the row for good, remove the entry from the file.

### Replicas that share a store

The store records the last revision and the digest of the block it applied.
A replica applies its block only if the store accepts it.

| Case | What the proxy does |
|---|---|
| The `revision` is lower than the stored one. | Does not apply the block. Logs an error that starts `declared tenant policy not applied: the store already applied a newer revision`. |
| The `revision` is equal and the content is different. | Does not apply the block. Logs an error that starts `declared tenant policy not applied: the store applied this revision with other content`. |
| The `revision` is higher, or equal with the same content. | Applies the block. |

A refused block does not stop the proxy at start. The replica serves the rows
in the store. Raise `revision` on every edit, and roll the new file out to
every replica.

### Remove a tenant

When you remove a tenant from the block, the reconcile removes the rows that
the file wrote for it. It does not remove the keys of the tenant. If the
tenant still has live keys, the proxy logs a warning with their number. A key
of a tenant with no policy row gets `403` under the default
`auth.enforce.tenants_without_policy: deny`. Revoke the keys with
`DELETE /tenants/{id}`.

The `auth.keys` list is still fixed at start. A `SIGHUP` that changes it is
refused.

### Errors

The load is strict. An unknown field fails with its full dotted path, at
start and on `SIGHUP`. A failed `SIGHUP` keeps the previous config.

| Error text | Cause |
|---|---|
| ``unknown field at `auth.declared_policy.bogus` `` | A field that does not exist. |
| ``invalid value at `auth.declared_policy.revision`: must be at least 1`` | `revision` is 0. A missing `revision` is also an error. |
| ``invalid value at `auth.declared_policy.tenants[0].budget.max_usd`: is a YAML number with a fraction; quote it as a string, for example "12.50", so no digit is lost to floating point`` | A `max_usd` that is not quoted. |
| ``invalid value at `auth.declared_policy.tenants[0].scoped_budgets[0].providers[0]`: `openia` is not an entry in the top-level `providers` map`` | A provider name with a typo. |
| ``invalid value at `auth.declared_policy.tenants[0].limits`: `auth.enforce.limits` is false, so this row would not be enforced; remove it or turn the control on`` | A declared row whose control is off. The same rule applies to `policy` with `enforce.model_policy`, and to `budget` and `scoped_budgets` with `enforce.spend`. |

A start can also fail with `the declared tenant policy could not be applied`
at `typed_config.declared_policy`. The store could not take the block. Fix
the store, then start again.

### Downgrade

A store that holds a row written by the file cannot be read by an older
build. The older build fails to load the store and says so. The row versions
are 2 for the model policy, 3 for the tenant budget, 4 for the scoped
budgets, and 3 for the limits. A row written by an admin call keeps its old
version.

Before a downgrade, do one of these for every declared tenant:

1. Remove the tenant from `auth.declared_policy`, and reload. The reconcile
   removes the rows that the file wrote.
2. Or write each row with an admin call. The row becomes admin-owned and
   keeps its old version.

A store with no file row stays readable. Redis adds the keys
`{ns}:tenant_sources` and `{ns}:declared_policy`. The embedded store adds
the table `declared_policy`. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/#declare-budgets-in-the-config-file)
for the budget side.

## Limitations

- A reload cannot change the settings that the table marks as needing a
  restart. The proxy refuses the whole reload instead.
- A reload does not catch every error. See "Errors that a reload does not
  catch".

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## SIGTERM after a reload

A `SIGHUP` reload does not change the shutdown sequence. A `SIGTERM` sent
after one or more reloads still drains and exits cleanly. See
[Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/) for what that
sequence does.

## Implementation notes

For maintainers. The `reload` function is in `crates/proxy/src/main.rs`.

- Tests in `crates/proxy/tests/reload.rs`:
  `sighup_with_a_broken_config_keeps_serving_and_logs_error` (the process
  stays alive and the listener keeps accepting),
  `sighup_with_an_unchanged_config_is_harmless`,
  `sighup_that_moves_the_admin_listener_is_refused_by_name`,
  `snapshot_version_advances_across_reloads`,
  `sighup_reload_is_reflected_in_config_dump_and_clusters`, and
  `sigterm_after_a_reload_still_drains_and_exits_cleanly`.
- `start_admin_registers_its_handle_into_the_shared_registry` in
  `crates/proxy/src/main.rs` covers the shared snapshot registry.
- Rate card tests in `crates/proxy-filters/src/usage_filter/rate_card_tests.rs`:
  `without_a_store_a_changed_configured_card_is_installed_on_reload`,
  `without_a_store_a_reload_that_did_not_change_the_card_keeps_a_put_card`, and
  `with_a_store_a_reload_never_replaces_the_stored_card`.
- The accept loop in `crates/proxy-core/src/listener.rs` reads the global
  connection limit.
- Declared tenant policy: `ControlPlane::declare` and
  `ControlPlane::reconcile_declared_now` in
  `crates/proxy-control/src/control.rs`, the planner in
  `crates/proxy-control/src/declared.rs`, and the dialect checks in
  `crates/proxy-simple-config/src/lower/declared_policy.rs`. Tests:
  `crates/proxy/tests/declared_policy_e2e.rs`,
  `crates/proxy-control/src/declared/tests.rs`, and
  `crates/proxy-simple-config/tests/declared_policy.rs`.
