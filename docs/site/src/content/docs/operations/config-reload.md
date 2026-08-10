---
title: Config reload
summary: SIGHUP re-reads the config file a running proxy booted with and
  publishes a new snapshot. A config that fails to parse or validate leaves
  the proxy serving the previous snapshot and logs the full error.
last_updated: 2026-08-09
related:
  - /configuration/configuration-file/
  - /observability/metrics-and-stats/
  - /operations/draining-and-shutdown/
---

# Config reload

llm-proxy re-reads its config on `SIGHUP`. There is no file-system watcher —
nothing reloads automatically when the file changes on disk — so a reload
only happens when something sends the signal:

```sh
kill -HUP <pid>
```

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
   [Metrics and /stats](/observability/metrics-and-stats/).
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

The admin server's `/config_dump` and `/clusters` endpoints do **not**
reflect a reload: they read a separate snapshot handle, taken once at
startup, that a `SIGHUP` reload never publishes into
(`crates/proxy/src/main.rs`'s `start_admin` builds its own
`WorkerConfigHandle` from the boot snapshot; `reload`'s `publisher.publish`
only reaches the handles `WorkerPool::spawn` created for workers,
`crates/proxy-core/src/runtime.rs`). If you need to confirm a reload took
effect, check the data plane itself (a new listener port becoming
connectable, or `/stats` picking up a new cluster) or the `SIGHUP: config
reload succeeded` log line, not `/config_dump`.

## SIGTERM after a reload

A `SIGHUP` reload does not disturb the shutdown/drain sequence: a `SIGTERM`
sent after one or more reloads still drains and exits cleanly, proven by
`sigterm_after_a_reload_still_drains_and_exits_cleanly` in
`crates/proxy/tests/reload.rs`. See
[Draining and shutdown](/operations/draining-and-shutdown/) for what that
sequence does.
