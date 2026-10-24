---
title: Stability and versioning
description: "What the 1.x releases keep stable for a --config deployment, the test that holds each surface fixed, what is not covered yet, and how deprecation works."
summary: The 1.x compatibility promise covers the --config dialect and the
  binary's operator surfaces. Each stable surface has a contract test. This
  page lists those surfaces, the surfaces that are not covered yet, the
  semantic versioning rules, and the deprecation rule.
lastUpdated: 2026-10-23
related:
  - configuration/configuration-file
  - configuration/strict-config-mode
  - reference/cli
  - reference/metrics
  - help/limitations
---

The 1.x releases follow one rule: you can upgrade from one 1.x release to a
later 1.x release without a change to your config file, your dashboards, or
your scripts. This page tells you which surfaces that rule covers. It also
tells you which test holds each surface fixed, and which surfaces have no
such test yet.

## At a glance

- **Covered:** the `--config` dialect and the operator surfaces of the
  binary that a contract test holds fixed.
- **Not covered:** Envoy mode. This is a bootstrap file loaded with `-c`,
  xDS, and the `type.llmproxy.dev` filter type URLs.
- **Not covered yet:** surfaces that have no contract test. See
  [Not covered by the compatibility promise yet](#not-covered-by-the-compatibility-promise-yet).
- **Deprecation:** a deprecated field or flag continues to work and logs a
  warning for at least one minor release. Only a major release removes it.
- **Check before you upgrade:** run the new binary with `--mode validate`
  on your config file.

## Scope

The promise applies to a proxy that you start with `--config <file>`. The
file uses the llmproxy dialect, which the
[Configuration file](/docs/llm-proxy/configuration/configuration-file/) page
describes.

Envoy mode is outside the promise. Envoy mode includes:

- An Envoy bootstrap file that you load with `-c` or `--config-path`.
- Configuration that the proxy receives over xDS.
- The `type.llmproxy.dev/...` type URLs in an Envoy `typed_config`.

These can change in a minor release. The
[Limitations](/docs/llm-proxy/help/limitations/#available-only-in-envoy-mode)
page lists what only Envoy mode reaches.

## Stable surfaces

A surface is stable only when a test fails if the surface changes. Each
surface below has such a test. The four golden files are in
`crates/proxy/tests/golden/`. Each one lists one item per line, and each
starts with a header that names what it does not cover. The test fails when
the code produces a line that the file does not have, or when the file has a
line that the code does not produce.

| Surface | What is fixed | Source of truth | Test |
|---|---|---|---|
| Config dialect | The schema: field names, types, allowed values, and required fields. | `schema/llmproxy-v1.schema.json` | `every_shipped_dialect_config_validates_against_the_schema_and_parses` (`crates/proxy-simple-config/tests/schema_gate.rs`) |
| Config compatibility | Every dialect example that v0.7.0 shipped loads, unedited, with `--mode validate`. | `crates/proxy/tests/fixtures/v0.7.0/` | `every_v0_7_0_dialect_example_loads_with_one_version_deprecation_warning` (`crates/proxy/tests/config_compat.rs`) |
| Command line | Flag names, short forms, value names, the allowed values of a flag, positional arguments, and subcommands. | `cli_flags.golden` | `golden_cli_flags` (`crates/proxy/src/main.rs`) |
| Metrics | Metric family names, types, and label names, as `GET /stats/prometheus` renders them. | `prometheus_metrics.golden` | `golden_prometheus_metric_names` (`crates/proxy/tests/contract_golden_e2e.rs`) |
| Admin API paths | Each admin path and the HTTP methods that the admin listener answers on it. | `admin_routes.golden` | `golden_admin_routes` (`crates/proxy/tests/contract_golden_e2e.rs`) |
| Access-log keys | The keys of each line that `observability.access_logs.format: json` writes. | `access_log_json_keys.golden` | `golden_access_log_json_keys` (`crates/proxy/tests/contract_golden_e2e.rs`) |

The schema is the normative definition of the dialect. The
[Configuration field reference](/docs/llm-proxy/configuration/reference/) is
generated from it.

The proxy is strict. It refuses a field that it does not know. Thus a config
that uses a field from a later 1.x release does not load in an earlier 1.x
release. The promise is for upgrades, not for downgrades.

## Not covered by the compatibility promise yet

These surfaces have no contract test. They can change in a minor release.
Do not build an integration that depends on them without a test of your own.

Command line:

- Environment variables, for example `LLMPROXY_ADMIN_TOKEN`,
  `LLMPROXY_ADMIN_UI_DIR`, and `LLMPROXY_AUTH_SECRET`.
- Exit codes.
- The help text and the default values of flags.
- The output of `--mode translate` and `--mode keygen`.

Metrics:

- Label values. Only label names are fixed.
- A label name that only a different outcome adds to a family. The golden
  file records the label sets that its test traffic produces.
- The metric families that the test traffic does not reach. A family appears
  on `/stats/prometheus` only after the proxy records a value in it. The
  golden file names these families:
  - `llmproxy_control_plane_load_duration`,
    `llmproxy_control_plane_load_payload_bytes`, and
    `llmproxy_control_plane_load_rows` (Redis auth store)
  - `llmproxy_realtime_usage_missing_total` (realtime sessions)
  - `llmproxy_guardrail_checks_total` (guardrails)
  - `llmproxy_chargeback_tags_dropped_total` (chargeback tags)
  - `llmproxy_tenant_credential_requests_total` and
    `llmproxy_provider_credential_requests_total` (tenant and minted
    credentials)
  - `llmproxy_router_max_output_tokens_rejected_total` (`max_output_tokens`)
  - `llmproxy_router_session_affinity_total` (session affinity)
  - `llmproxy_trace_segments_uploaded_total` and
    `llmproxy_trace_upload_failures_total` (trace upload to S3)
  - `llmproxy_unmetered_endpoint_refused_total` (unmetered endpoints)
  - `ext_authz` (Envoy mode only)
- Output of the other `/stats` formats. Only `/stats/prometheus` has a
  contract test.

Admin API:

- Request bodies, response bodies, and status codes.
- Query parameters.
- The `/ui/<asset>` paths and the `/` redirect. These exist only when the
  admin UI bundle is loaded.

Access logs:

- Values. Only the keys are fixed.
- The `text` format string.
- The lines that the proxy writes for realtime sessions.

Responses to clients:

- Error bodies that the proxy generates.
- Response headers that the proxy adds.

Each item on this list leaves the list only when a contract test covers it.

## Semantic versioning

Version numbers have the form `MAJOR.MINOR.PATCH`. The rules apply to the
stable surfaces above.

| Release | What it can change |
|---|---|
| Patch, for example 1.2.0 to 1.2.1 | Bug fixes and security fixes. It does not add, remove, or rename an item on a stable surface. |
| Minor, for example 1.2.1 to 1.3.0 | Everything that a patch can change. It can add config fields, flags, metric families, admin paths, admin methods, and access-log keys. It can deprecate a field or a flag. It does not remove or rename an item on a stable surface, and it does not change the label names of an existing metric family. |
| Major, for example 1.3.0 to 2.0.0 | It can remove or rename an item on a stable surface. It removes only items that a minor release deprecated before. |

A bug fix can change behavior that a config relied on, for example when the
proxy accepted a value that the schema did not permit. The CHANGELOG records
each such change.

A change to a golden file is a deliberate, reviewed edit. The test message
tells the developer to run `make golden` and to commit the reviewed diff with
a CHANGELOG entry (`crates/proxy/tests/common/golden.rs`).

## Deprecation

A deprecated field or flag continues to work. The proxy logs a warning each
time it loads a config that uses it. The warning names the replacement. The
item stays for at least one minor release before a major release removes it.

### Example: `version: 0`

The schema version before 1.0 was `version: 0`. Version `1` has the same
fields, so the only change to an older file is this line:

```diff
-version: 0
+version: 1
```

A `version: 0` file loads in every 1.x release. At each load, `--mode
validate` and `serve` print this warning to standard error:

```text
warning: `version`: `version: 0` is deprecated; set `version: 1`. The rest of the file is valid for version 1 unchanged, and version 0 still loads in every 1.x release
```

On a reload with `SIGHUP`, the proxy logs the same message as a
`config reload warning` log event.

Any other value fails at load with an error at the `version` field:

```text
this build understands schema version 1 (and the deprecated 0), not 2
```

## Check a config before you upgrade

Do these steps before you replace the binary in production.

1. Install the new binary in a separate location.
2. Run `--mode validate` with the new binary on your current config file.
   This mode does the same load steps as `serve`. It does not open a
   listener.

   ```bash
   ./llm-proxy-new --config llmproxy.yaml --mode validate
   ```

3. Make sure that standard output shows a line that starts with
   `configuration 'llmproxy.yaml' OK`.
4. Read each `warning:` line on standard error. A deprecation warning names
   the replacement. Change the config before the next major release.
5. Make sure that each flag in your start command is in the output of
   `./llm-proxy-new --help`.
6. Read the CHANGELOG entries between your version and the new version.

`--mode validate` does not do all start-time checks. A port that is in use,
and the `--service-node` checks for the ledger and trace export, fail only in
`serve`. See [CLI reference](/docs/llm-proxy/reference/cli/#validate).

## Limitations

- Envoy mode has no compatibility promise.
- The promise covers only the surfaces that a contract test holds fixed.
  The list of surfaces that are not covered yet is above.
- A downgrade to an earlier 1.x release can fail on a field that the
  earlier release does not know.
- See [Limitations](/docs/llm-proxy/help/limitations/) for what the proxy
  does not do.
