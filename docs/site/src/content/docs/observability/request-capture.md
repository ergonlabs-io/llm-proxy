---
title: Request capture
description: "Write one metadata record for each request (no bodies) to a JSON-lines file."
summary: Opt-in request metadata records written to a JSON-lines file, then
  the record fields, loss accounting, and metrics.
lastUpdated: 2026-10-21
related:
  - observability/overview
  - observability/access-logs
  - observability/metrics-and-stats
  - reference/cli
---

Request capture writes one metadata record for each completed request. A
record names the tenant, the user, the requested model, the selected provider
and model, the status, the token usage, and the cost. A record holds no
request body, no response body, and no headers. To export bodies, see
[Request and response body export](/docs/llm-proxy/observability/trace-export/).

Capture is off by default. It starts only when you give the proxy a
JSON-lines file to write. The file is the only destination. Earlier releases
had a capture agent as a second destination. It is removed. To export bodies,
use [body export](/docs/llm-proxy/observability/trace-export/).

## At a glance

- **How to turn on**: start the proxy with `--request-records-file <PATH>`.
  The `llmproxy` config file has no field for it.
- **Default when unset**: the proxy writes no records.
- **Failure mode**: fails open. A full queue or a failed write drops records
  and counts them. Forwarding never waits.

**A record contains end-user identities and model history.** Protect the
destination.

## Write records to a file

Use this procedure to turn capture on, make one record, and read it.

1. Choose a file path. The directory must exist, and the proxy user must be
   able to write to it.

2. Start the proxy with `--request-records-file`.

   ```sh
   llm-proxy --config llmproxy.yaml \
     --request-records-file /var/lib/llmproxy/request-records.jsonl
   ```

3. Send one request through the proxy. Use any route in your config. This
   example assumes a route for `gpt-4o-mini` and the default port `53421`.

   ```sh
   curl --max-time 30 http://127.0.0.1:53421/v1/chat/completions \
     -H "content-type: application/json" \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
   ```

4. Read the last record. The proxy writes each record as one JSON line.

   ```sh
   tail -n 1 /var/lib/llmproxy/request-records.jsonl | jq .
   ```

The record looks like this. The example is abridged and the values are
illustrative. A real record has more fields. See
[What a record holds](#what-a-record-holds).

```json
{
  "schema_version": 1,
  "request_id": "<request id>",
  "instance_id": "<instance id>",
  "record_seq": 1,
  "tenant_id": "default",
  "user_id": null,
  "key_id": null,
  "method": "POST",
  "requested_model": "gpt-4o-mini",
  "selected_provider": "openai",
  "selected_model": "gpt-4o-mini",
  "status": 200,
  "termination": "complete",
  "usage": {
    "input_tokens": 9,
    "output_tokens": 12,
    "completeness": "complete",
    "provenance": "provider"
  },
  "cost": {"amount": 1200, "unit": "nanodollars", "currency": "USD", "kind": "list"},
  "attempts_truncated": false
}
```

If the config has no price for the model, `cost` is `null`. A record never holds the
prompt or the answer.

### Destination permissions

The proxy creates a new file with mode `0600`. The file is a regular file.
The proxy refuses to start with `cannot start metadata collector: metadata
destination must be a regular file` if the path is a directory or another
kind of file. If the file already exists, the proxy keeps its mode. Set the
mode of an existing file yourself.

### Rotation and retention

You rotate the file. The proxy does not rotate, expire, or compress it. The
proxy opens the file once at start and appends to it. It does not reopen the
file on `SIGHUP`.

- A file that you rename keeps receiving records, because the proxy holds the
  open file. Renaming alone does not start a new file.
- A copy-then-truncate rotation works with the append mode of the proxy.
- To start on a new file, change the path and restart the proxy.

Set the retention and the access control of the old files in your own tooling.

### Delivery limits

File delivery is best effort. It is not a billing record. For billing, use the
[billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/).

- The proxy hands each record to a writer thread through a queue of 1,024
  records. A full queue drops the new record and counts it. Forwarding does
  not wait.
- The proxy does not call `fsync`. A successful write is not a durability
  acknowledgement.
- After one failed write, the proxy stops accepting records for the rest of
  the process. It discards the queued records and counts them in
  `llmproxy_metadata_dropped{reason="drained_after_close"}`. Forwarding
  continues.
- On shutdown, the proxy writes the queued records for up to 5 seconds
  (less on a fast exit). A process that `SIGKILL` stops loses the queued
  records.

See [Check that no record was lost](#checking-that-no-record-was-lost) and
[Record delivery metrics](#record-delivery-metrics).

### Flags

| Flag | Required | Default | What it does |
|---|---|---|---|
| `--request-records-file <PATH>` | no | none | Append JSON lines to this file. |
| `--request-record-max-attempts <N>` | no | `64` | Attempt summaries to keep for each record. Range 1 to 64. Needs `--request-records-file`. |

The flags are read at start. A reload does not change them. The `llmproxy`
dialect has no capture field.

## What a record holds

These are some of the fields of a record:

| Field | Meaning |
|---|---|
| `request_id`, `event_id`, `instance_id` | Identify the request, the record, and the proxy instance. |
| `record_seq` | The record's number within its `instance_id`: 1, 2, 3, and so on, in the order the delivery path wrote the records. A gap means a record that was numbered but not delivered. Absent in records from older builds. |
| `tenant_id`, `user_id`, `key_id` | Identify who made the request. `user_id` and `key_id` can be `null`. `tenant_id` is `default` when the request had no tenant (no auth configured, or a credential that names none), and `unauthenticated` when the auth filter refused it; `error_category` then gives the reason, for example `auth_unknown_key`. Both names are reserved. |
| `client_address` | The client address, without a port. It is the TCP peer address, except behind [`listen.trusted_hops`](/docs/llm-proxy/configuration/reference/#listener), where it is the `x-forwarded-for` address that the trusted proxies vouch for. `client-ip` limits use the same address. Absent in records from older builds. |
| `requested_model` | The model name the client sent. |
| `selected_provider`, `selected_model` | The provider and model the proxy dialled. |
| `status`, `termination`, `error_category` | How the request ended. `error_category` is the response code detail string. A stream whose downstream connection closed is `termination: downstream_disconnect` with flag `DC`, and `error_category` says which side closed it: `downstream_remote_disconnect` when the client left, `downstream_local_disconnect` when the proxy cut it at shutdown (the end of `--drain-time-s`, or a second termination signal). |
| `usage`, `cost` | Token counts and cost. Both can be `null`. |
| `usage.completeness`, `usage.provenance` | `complete` for a finished response. `partial` for a stream cut off before the provider's final usage: the counts are then the provider's figures where they arrived and estimates (4 bytes per token) for the rest. `provenance` is `provider`, or `estimate` when any count was estimated; `usage.input_estimated` and `usage.output_estimated` say which. |
| `cost.kind` | `list` for a rate-card price of provider-reported usage, `estimate` when it prices estimated usage. A partial record is charged to spend and token limits at this estimate. |
| `upstream_response_id` | The provider's own id for the response, bounded to 256 bytes. `null` when absent. |
| `upstream_usage` | The provider's `usage` object exactly as sent, embedded as JSON (the last one, for a stream). Evidence only: cost never comes from it. `null` when absent or over 4096 bytes. |
| `attempts`, `attempts_truncated` | One summary for each provider attempt. Excess attempts are cut and flagged. |

## Checking that no record was lost

Each `instance_id` is one proxy process. When metadata delivery stops, the
proxy logs one line with `event="metadata_delivery_summary"`. The line has
`instance_id`, `last_record_seq`, `accepted`, `written`, `failed`, `unwritten`,
the admission drops (`dropped_capacity`, `dropped_oversize`, `dropped_invalid`,
`dropped_closed`), and `timed_out`. The level is `WARN` when a record was lost
or the flush timed out, and `INFO` otherwise.

To reconcile, for each `instance_id`:

1. Expect records with `record_seq` from 1 to `last_record_seq`, with no gaps.
2. Expect a summary line with nothing lost.
3. If there is no summary line, the process was killed (for example `SIGKILL`
   after a container stop timeout). The records after the last `record_seq`
   that arrived are unknown.

Give the proxy a stop timeout longer than `--drain-time-s`, so that it can
drain and write the summary.

### Record delivery metrics

These series are on `/stats/prometheus` with the `envoy_` prefix. See
[Metrics and stats](/docs/llm-proxy/observability/metrics-and-stats/). The proxy creates them at start,
so an idle proxy shows `0` and not a missing series.

| Metric | Labels | Meaning |
|---|---|---|
| `llmproxy_metadata_admission` | `outcome`: `accepted`, `capacity_exceeded`, `closed`, `oversize`, `invalid` | Whether the queue took the record. `oversize`: the record alone passed the size limit. `invalid`: the record failed schema validation. |
| `llmproxy_metadata_dropped` | `reason`: `drained_after_close` | Records that the queue accepted and the proxy later discarded without a write. |
| `llmproxy_metadata_queue_depth` | none | Records in the queue. |
| `llmproxy_metadata_queue_capacity` | none | Queue size. `0` means capture is not configured. |
| `llmproxy_metadata_written` | none | Records delivered. An append to the file. |
| `llmproxy_metadata_write_failures` | none | Write failures, or deliveries with an unknown result. |

Alert on a rising `llmproxy_metadata_write_failures` and on
`llmproxy_metadata_admission{outcome="capacity_exceeded"}`.

## Limitations

- The `llmproxy` config file has no field for request records. Use the flag.
- The proxy does not rotate, expire, compress, or reopen the file.
- Delivery is best effort. A `SIGKILL` loses the queued records.
- A record holds no request body and no response body.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Each behavior above has this source or test.

- File sink: `crates/proxy-observability/src/metadata.rs`. The module doc
  states the best-effort contract. `MetadataDelivery::start` sets mode `0600`
  and the append open. The writer thread stops admission after a failed write
  (`close_on_failure`) and stamps `record_seq`.
- Flags: `crates/proxy/src/main.rs`, `Args` and the request-record setup in
  `serve`.
- Record type: `RequestRecord` in `crates/proxy-observability/src/records.rs`.
  `capture_policy_version` stays in the schema and is always `null`.
- The retired `node.metadata["io.llmproxy.capture"]` key is rejected in
  `crates/proxy-config/src/lower.rs`; test
  `crates/proxy-config/tests/capture_retired.rs`.
- Drain and reload behaviour: `crates/proxy/tests/request_records_file_e2e.rs`.
- Metric definitions: `crates/proxy-observability/src/stats.rs`.
