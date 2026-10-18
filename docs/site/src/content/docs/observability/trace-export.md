---
title: Trace export
summary: Opt-in export of request and response bodies for analytics and
  fine-tuning. Covers the two consent switches, what a trace holds, the line
  format, local and S3 storage, sizing, every loss reason and metric, the
  emergency switch, and what is not available.
last_updated: 2026-10-17
related:
  - ../observability/request-capture/
  - ../observability/metrics-and-stats/
  - ../observability/admin-endpoints/
  - ../authentication/virtual-keys/
  - ../configuration/reference/
---

# Trace export

Trace export writes the body of each request and the body of its response to
compressed JSON-lines files. You use the files to analyse agent behaviour and
to fine-tune your own models.

Trace export is best effort. It is for analytics. It is never for billing.
The billing ledger is the only record of charges. Nothing reads a trace back
to enforce a limit or to charge a tenant. A lost trace is a counted loss, not
an accounting error.

**Warning.** There is no redaction in this version. A tenant that opts in
consents to raw capture of its request and response bodies. Prompts,
completions, tool arguments, and any secret inside them go into the files
unchanged. Protect the directory and the bucket.

This page is not the metadata record. For the record that holds no bodies,
see [Request capture](../request-capture/).

## Two switches, both required

A request is captured only when both switches are on. When either is off,
the proxy captures nothing, counts nothing, and logs nothing for that
request.

| Switch | Who sets it | How |
|---|---|---|
| Export | The operator | The `observability.traces` block in the config file. It requires the `auth` block. |
| Opt-in | Each tenant | `PUT /tenants/{id}/trace_export` on the admin server. |

The dialect refuses `observability.traces` without `auth`. The error is
`observability.traces: requires auth: tenants opt in through tenant policy`
(`crates/proxy-simple-config/src/lower.rs:495-500`).

### Opt in a tenant

The opt-in call needs the admin token. Set `LLMPROXY_ADMIN_TOKEN` before the
proxy starts.

```bash
curl -X PUT http://$ADMIN_ADDR/tenants/acme/trace_export \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -d '{"schema_version":1,"enabled":true}'
```

The answer is `204`. The body accepts only `schema_version` (must be `1`) and
`enabled`. An unknown field gives `400`
(`crates/proxy-admin/src/server.rs:2840-2866`). To read the flag, send
`GET /tenants/{id}/trace_export`. The answer is
`{"schema_version":1,"tenant":"acme","enabled":true}`.

These rules apply to the opt-in:

- The tenant must exist. An unknown tenant gives `404`. A tenant that
  authenticates with a JWT must be created first by the operator with
  `POST /tenants`.
- A tenant id that is too long gives `400` with `tenant_id_too_long`. The
  limit is 200 bytes for `tenant=` plus the percent-encoded id
  (`crates/proxy-observability/src/traces/mod.rs`, `MAX_TENANT_DIR_BYTES`).
- An absent flag is not consent. A new tenant is not opted in.
- With the default `in_memory` store, the flag resets to off when the proxy
  restarts. Use the `persistent` or `shared` store to keep it. See
  [Virtual keys](../../authentication/virtual-keys/).
- An opt-out reaches the other replicas on their next policy poll. The
  default poll interval is 48 seconds.
- A request keeps the flag it had when it was admitted. An opt-out does not
  stop a request that is already in flight from being captured.
- For a JWT request, the proxy withholds the opt-in while the policy snapshot
  is stale. Each such request adds one to
  `llmproxy_trace_consent_stale_total`
  (`crates/proxy-filters/src/auth.rs:805-830`).

A request with no authenticated tenant is never captured.

## What a trace holds

A trace holds two bodies:

- The request body as the proxy received it, before any rewrite by a filter.
- The response body as the proxy delivered it to the client.

Each body is cut at a cap for each request (`max_request_body_bytes` and
`max_response_body_bytes`). A body over its cap is kept up to the cap. The
trace is then marked `partial`.

A trace never holds:

- Headers, in either direction.
- Bytes of an upgraded (WebSocket) session. The proxy does not capture an
  upgrade request. It counts `dropped{reason="unsupported_protocol"}`.
- A request refused before authentication (for example `401`, `408`, `413`).
  No tenant is known for it.
- Upstream bodies, or the bodies of failed attempts. A retried or failed-over
  request gives one trace, with the response that the client received.

The proxy captures a refusal that it sends after authentication, such as a
`403` for a model grant or a `429` for a limit. That reply is the response
that the tenant received. The request body of each refused request is kept
(`a_local_reply_after_consent_is_captured` in
`crates/proxy-http/src/filter_manager/trace_tests.rs`).

The request thread copies bytes and hands them over. It does not parse,
compress, or write. A separate exporter thread does that work.

## Enable trace export

1. Set the secrets in the environment of the proxy.

   ```bash
   export LLMPROXY_AUTH_SECRET=change-me
   export LLMPROXY_ADMIN_TOKEN=change-me-too
   export OPENAI_API_KEY=sk-...
   ```

2. Write the config. This example writes segments to a local directory.

```yaml
version: 0
listen: 127.0.0.1:8080
admin: 127.0.0.1:9901
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
observability:
  traces:
    directory: /var/lib/llmproxy/traces
    max_disk_bytes: 10737418240
    max_age: 168h
```

3. Start the proxy with a node id. The node id names each segment, so it must
   be unique for each replica.

   ```bash
   llm-proxy --config llmproxy.yaml --service-node proxy-a
   ```

4. Create a tenant, mint a key, and opt the tenant in.

   ```bash
   curl -X POST http://127.0.0.1:9901/tenants \
     -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
     -d '{"tenant":"acme"}'
   curl -X POST http://127.0.0.1:9901/keys \
     -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
     -d '{"tenant":"acme","key_id":"acme-1"}'
   curl -X PUT http://127.0.0.1:9901/tenants/acme/trace_export \
     -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
     -d '{"schema_version":1,"enabled":true}'
   ```

5. Send requests with the key. The proxy writes the first segment when it
   seals the segment. A segment seals after `segment_max_age` (5 minutes by
   default), or when the proxy stops. To see a file at once, stop the proxy
   with `SIGTERM`.

The proxy refuses to start in these cases:

| Cause | Message starts with |
|---|---|
| No node id | `node.metadata["io.llmproxy.traces"]: trace export requires a node id (--service-node or node.id)` |
| Another process holds the directory | `node.metadata["io.llmproxy.traces"].directory: another process holds` |

The node id must be 1 to 128 bytes, and not `-`
(`crates/proxy-observability/src/traces/segment.rs`, `OpenError`).

The block is fixed at start. A reload that changes it is refused, the proxy
logs `cannot change on reload`, and the previous configuration keeps serving
(`crates/proxy/src/main.rs:2059-2068`). Restart the proxy to change it.

### Envoy mode

Envoy mode takes the same fields in `node.metadata["io.llmproxy.traces"]` of
a `-c` bootstrap. Durations are numbers of seconds. The `s3` field is a
nested object. `--permissive` does not relax this block. The dialect lowers
to this key, so the two modes run the same engine.

```yaml
node:
  id: proxy-a
  metadata:
    io.llmproxy.traces:
      directory: /var/lib/llmproxy/traces
      max_disk_bytes: 10737418240
      max_age: 604800
```

Envoy mode does not check for an `auth` filter when it loads the block. With
no `auth` filter, no tenant can opt in, and the block captures nothing.

## Configuration

All fields are in `observability.traces`. The schema
(`schema/llmproxy-v0.schema.json`, `$defs/Traces`) and the
[configuration reference](../../configuration/reference/) are the source for
this table. An unknown field is an error with its full path.

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `directory` | string, absolute path | none | yes | Segment directory. Created `0700`. One proxy process uses it at a time. |
| `max_disk_bytes` | integer, 1 MiB to 1 PiB | none | yes | Budget for every segment on disk, open or sealed, sent or not. |
| `max_age` | duration, up to 10 years | none | no | Directory destination only. Delete sealed segments older than this. Refused with `s3`. |
| `codec` | `gzip` or `zstd` | `gzip` | no | Segment compression. |
| `zstd_window_log` | integer, 20 to 27 | `24` | no | log2 of the zstd window. Only with `codec: zstd`. |
| `max_request_body_bytes` | integer, 1 KiB to 64 MiB | `1048576` | no | Cap for the request body of one request. |
| `max_response_body_bytes` | integer, 1 KiB to 64 MiB | `4194304` | no | Cap for the response body of one request. |
| `max_memory_bytes` | integer, 1 MiB to 1 TiB | `268435456` | no | Cap for every retained body byte, in flight and queued. At least the two body caps together. |
| `max_queued_traces` | integer, 1 to 1048576 | `4096` | no | Cap for captures in flight plus queued. |
| `segment_max_bytes` | integer, 1 MiB to 1 GiB | `67108864` | no | Seal a segment when its compressed size reaches this. |
| `segment_max_age` | duration, 10s to 1h | `5m` | no | Seal a segment when it is this old. |
| `max_open_segments` | integer, 1 to 4096 | `64` | no | Open (tenant, date) segments. The least recently written is sealed beyond this. |
| `s3` | object | none | no | S3 destination. See [S3 upload](#s3-upload). |

The load checks (`crates/proxy-observability/src/traces/config.rs`,
`validate`) also refuse these:

- `max_memory_bytes` smaller than the two body caps together.
- `segment_max_bytes` smaller than the largest line. See [Sizing](#sizing).
- `max_disk_bytes` smaller than 2 x `max_open_segments` x
  `segment_max_bytes`.
- `max_age` together with `s3`.
- `zstd_window_log` with `codec: gzip`.
- `max_open_segments` x 2^`zstd_window_log` above 2 GiB.

## The line format

Each request gives one JSON line. The line is schema version 1.

```json
{"schema_version":1,
 "event_id":"0f3c...:terminal",
 "instance_id":"proxy-a",
 "record":{"...":"the request record, unchanged"},
 "capture":{"state":"complete","reasons":[]},
 "request":{"content_type":"application/json","representation":"wire",
            "body":{"model":"gpt-4o","messages":[]}},
 "response":{"status":200,"streamed":true,
             "content_type":"text/event-stream","representation":"wire",
             "body":{"object":"chat.completion","choices":[]}}}
```

(The example is cut for length. Real lines are on one line.)

| Field | Meaning |
|---|---|
| `schema_version` | The version of the line format. It is `1`. |
| `event_id` | The same value as `record.event_id`. Use it to remove duplicates. |
| `instance_id` | The node id of the proxy. The `instance_id` inside `record` is the text `proxy`. |
| `record` | The terminal request record, as the record sink gets it. It holds tenant, user, model, provider, usage, and cost. |
| `capture.state` | `complete` or `partial`. |
| `capture.reasons` | Why the state is `partial`. See [Partial reasons](#partial-reasons). |
| `request`, `response` | One object for each direction. |
| `content_type`, `content_encoding` | The header values. Absent when the header is absent. `content_encoding` is absent for identity. |
| `representation` | `wire` for the bytes as delivered. `decoded` when the proxy inflated them. |
| `body` | The body as embedded JSON. Present when the body is complete, valid JSON. |
| `body_text` | The body as a string. Used when it is valid UTF-8 and not complete JSON. |
| `body_base64` | The body in base64. Used for any other bytes. |
| `status` | Response only. The HTTP status. |
| `streamed` | Response only. `true` when the response was `text/event-stream`. |

A line has exactly one of `body`, `body_text`, and `body_base64` for each
direction. A body cut at a cap is never given as `body`. It is given as
`body_text` or `body_base64`.

`capture.state` is `complete` only when both bodies are whole and, for a
stream, the final event was seen. The state does not depend on the status. An
error response can be `complete`.

Embedded JSON bodies keep their original text, without outer whitespace. A
reassembled Anthropic body has its keys sorted
(`internal-docs/trace-export-design.md`, section 15).

### Streams

The proxy captures an SSE response as delivered bytes. The exporter thread
then reassembles the events into the non-streaming response shape. It does
not keep the raw stream.

| Dialect and path | Result |
|---|---|
| `openai`, chat completions | A `chat.completion` object. Content, tool calls, finish reason, and usage are merged by choice index. |
| `openai`, legacy completions | A `text_completion` object with the text joined. |
| `openai`, Responses API (path ends in `/responses`) | The full response object from the final event. |
| `anthropic`, messages | A message object. Text, thinking, and tool input are joined by block. |
| Any other dialect, or an event shape that the proxy does not know | The delivered bytes as `body_text` or `body_base64`. The trace is `partial`. |

The proxy picks the dialect from the provider that it dialled
(`crates/proxy-observability/src/traces/reassemble.rs`,
`reassemble_response`). It does not guess a shape.

A body with `content-encoding: gzip` or `deflate` is inflated. The cap
applies to the inflated size. The direction then has
`"representation":"decoded"` and keeps the original `content_encoding`. Any
other encoding is exported as `body_base64` with `"representation":"wire"`.
The trace is `partial` with `content_encoding`
(`crates/proxy-observability/src/traces/exporter.rs`, `decode`).

## Storage

### Segment layout

Segments are files of JSON lines, compressed by the codec.

```text
<directory>/tenant=<t>/date=<yyyy-mm-dd>/<instance>-<epoch>-<seq>.jsonl.gz
```

`.jsonl.zst` replaces `.jsonl.gz` with the `zstd` codec. A file being
written has a leading `.` and the suffix `.open`. Read only sealed files.

- `<t>` is the tenant id and `<instance>` is the node id. The proxy
  percent-encodes both. Each byte outside `A-Z a-z 0-9 _ -` becomes `%XX`, so
  `.` and `/` never appear. The tenant `a/b` is `tenant=a%2Fb`.
- `date` is the UTC date of the end of the request.
- `epoch` is a start time in milliseconds. The proxy raises it past a saved
  mark on each start, so a name never repeats after a restart. `seq` counts
  segments inside one epoch.
- The directory is `0700` and the files are `0600`
  (`crates/proxy-observability/src/traces/exporter_tests.rs`,
  `a_captured_stream_becomes_one_line_in_a_sealed_private_segment`).

There is one open segment for each tenant and date. The proxy seals a segment
for these reasons:

| Seal reason | Cause |
|---|---|
| `size` | The next line would take the segment past `segment_max_bytes`. |
| `age` | The segment is `segment_max_age` old. |
| `date` | The UTC date changed. |
| `lru` | A new segment would pass `max_open_segments`. The least recently written segment is sealed. |
| `shutdown` | The proxy stops. |

Count them with `llmproxy_trace_segments_sealed_total`. If many `lru` seals
happen on young segments, the proxy logs a warning. It means more tenants
are active than `max_open_segments`, and the objects are small. Raise
`max_open_segments`. Do not lower `segment_max_age`.

Control files sit in the directory root: `.lock`, `.capture-disabled`, and
`.epoch-<instance>`. Do not delete them.

### One process for each directory

At start, the proxy takes an exclusive lock on `<directory>/.lock`. A second
process on the same directory does not start. Give each replica its own
directory.

A crash leaves `.open` files without an end. At the next start, the proxy
deletes every `.open` file in the directory. It adds the count to
`llmproxy_trace_segments_lost_total{reason="unsealed_at_start"}` and logs a
warning. A crash loses at most `segment_max_age` of lines for each open
segment.

### Retention for a directory

With no `s3` block, the files stay in the directory. The proxy deletes sealed
segments in two cases:

- A segment is older than `max_age`. It adds one to
  `llmproxy_trace_segments_expired_total{reason="age"}`.
- All segments together pass `max_disk_bytes`. The proxy deletes the oldest
  first. It adds one to `{reason="size"}`.

These deletions are the retention that you set. They are not losses.

### S3 upload

Add an `s3` block to upload each sealed segment and then delete it locally.
The proxy keeps the directory as a buffer for segments that are not yet
uploaded.

```yaml
version: 0
listen: 127.0.0.1:8080
admin: 127.0.0.1:9901
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
observability:
  traces:
    directory: /var/lib/llmproxy/traces
    max_disk_bytes: 10737418240
    s3:
      bucket: my-traces
      region: eu-west-1
      prefix: llmproxy
      access_key_id: ${TRACES_S3_KEY_ID}
      secret_access_key: ${TRACES_S3_SECRET}
```

The object key is `<prefix>/` followed by the segment path under
`<directory>`. For the example, a key is
`llmproxy/tenant=acme/date=2026-10-17/proxy-a-1760000000000-0.jsonl.gz`.
The upload is one `PUT` of the whole file with `content-type:
application/x-ndjson`. The request is signed with SigV4
(`crates/proxy-observability/src/traces/uploader.rs`).

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `bucket` | string | none | yes | 3 to 63 bytes of lowercase letters, digits, `.`, and `-`. |
| `region` | string | none | yes | At most 64 bytes of lowercase letters, digits, and `-`. The proxy never infers it. |
| `endpoint` | string | `https://s3.<region>.amazonaws.com` | no | `http://` or `https://` host with an optional port. No path, query, or user. |
| `path_style` | boolean | `false` | no | Use `https://<host>/<bucket>/<key>`. |
| `prefix` | string | empty | no | Key prefix. No leading or trailing `/`, and no empty, `.`, or `..` segment. |
| `access_key_id` | string | none | yes | Static access key id. |
| `secret_access_key` | string | none | yes | Static secret key. The proxy never logs it. |
| `session_token` | string | none | no | Token for temporary credentials. |
| `upload_timeout` | duration, 1s to 1h | `120s` | no | Deadline for one upload. |

Follow these rules:

- Put the credentials only in this block. Use `${ENV}` substitution. Do not
  write a literal key in the file.
- Use static keys. Instance roles (IMDS, IRSA, workload identity) are not
  supported.
- Use a bucket in the same region as the proxy. Upload to another region
  costs money for the data that leaves the region.
- Set `path_style: true` for MinIO and for most S3-compatible stores. A
  bucket name with a `.` also needs `path_style: true`. The load fails
  otherwise with `s3.path_style: must be true for a bucket name containing
  '.'`.
- Use an `https://` endpoint. For a plain `http://` endpoint to a host that
  is not loopback, the proxy logs `trace upload endpoint is plain http:
  request and response bodies travel unencrypted`. SigV4 keeps the secret off
  the wire, but the bodies travel in clear.
- Do not set `max_age`. The bucket lifecycle rules remove old objects.

**Tested stores.** The upload is tested only against a local test double
that checks the SigV4 signature and the key
(`crates/proxy-observability/src/traces/uploader_tests.rs`). AWS S3, Google
Cloud Storage, Cloudflare R2, and MinIO were not tested. Test your store
before you depend on it.

If an upload fails, the proxy adds one to
`llmproxy_trace_upload_failures_total` and retries. The retry uses
exponential backoff with jitter, from 1 second to 5 minutes. A `4xx` answer
is retried too, because you can fix a credential or a policy without a
restart. The reasons are `connect`, `timeout`, `status_4xx`, `status_5xx`,
and `io`.

While the store is down, sealed segments stay on disk. When all segments
reach `max_disk_bytes`, the proxy deletes the oldest unsent segment. It adds
one to `llmproxy_trace_segments_lost_total{reason="upload_backlog"}`. It adds
the lines of that segment to `llmproxy_trace_dropped_total{reason="upload_backlog"}`
when this process sealed it. After recovery, the proxy uploads the segments
that remain (`an_outage_drops_the_oldest_unsent_segment_and_recovery_uploads_the_rest`).

At shutdown, the uploader finishes the upload in progress if time allows.
Segments that are not sent stay on disk. The next start uploads them.

### Codecs

`gzip` is the default. Every warehouse loader reads it.

`zstd` makes smaller files. Agent turns resend the whole conversation, and
the turns of one tenant land in the same segment. A long zstd window removes
that repetition. A gzip window of 32 KiB cannot.

```yaml
observability:
  traces:
    codec: zstd
    zstd_window_log: 24
```

A window of 2^24 bytes is 16 MiB. Each open segment holds about one window
of encoder memory, plus a few MiB. Read these files with a decoder that
accepts the window. With the `zstd` command, pass `--long=<window_log>`.

```bash
zstd -d --long=24 -c segment.jsonl.zst > segment.jsonl
```

Check that your warehouse loader reads long-window zstd before you choose
this codec.

### Cost

Object stores charge for each request and for stored bytes. Trace export is
built for both.

- It writes few, large objects. A segment is sealed at 64 MiB compressed or
  5 minutes by default. It never writes one object for one request.
- Bodies go to files and to object storage only. No streaming bus (Kafka or
  an OTLP collector) carries them.
- Retention is the bucket's job. The proxy deletes nothing in a bucket.

This lifecycle rule moves objects to cheaper storage after 30 days and
deletes them after 365 days. It is an example. Adjust it to your policy.

```json
{
  "Rules": [
    {
      "ID": "llmproxy-traces",
      "Status": "Enabled",
      "Filter": { "Prefix": "llmproxy/" },
      "Transitions": [{ "Days": 30, "StorageClass": "STANDARD_IA" }],
      "Expiration": { "Days": 365 }
    }
  ]
}
```

Apply it with `aws s3api put-bucket-lifecycle-configuration --bucket
my-traces --lifecycle-configuration file://lifecycle.json`. Turn on bucket
encryption (SSE) for data at rest. The proxy does not encrypt the files.

## Sizing

The defaults need `max_disk_bytes` of at least 8 GiB. The rule is:

```text
max_disk_bytes >= 2 x max_open_segments x segment_max_bytes
```

With the defaults, that is 2 x 64 x 64 MiB = 8 GiB. The factor of 2 covers a
segment that passes `segment_max_bytes` by one encoder block, and bytes that
are written while the proxy seals.

Also, `segment_max_bytes` must be at least the largest line:

```text
largest line = ceil((max_request_body_bytes + max_response_body_bytes) / 3) x 4
               + 1 MiB
```

With the default caps, the largest line is 8039084 bytes (about 7.7 MiB). A
smaller `segment_max_bytes` fails to load, and the error gives the minimum.

To use less disk, lower `max_open_segments` or `segment_max_bytes`. This
example needs 512 MiB of disk:

```yaml
observability:
  traces:
    directory: /var/lib/llmproxy/traces
    max_disk_bytes: 536870912     # 2 x 8 x 32 MiB
    max_open_segments: 8
    segment_max_bytes: 33554432   # 32 MiB
```

Set `max_open_segments` to at least the number of tenants that are active at
one time. Fewer segments than tenants make small objects.

For a complete corpus, size the queue and memory for your peak traffic.
`max_queued_traces` limits captures in flight plus queued. `max_memory_bytes`
limits their body bytes. A request over either limit is dropped before the
proxy copies any byte.

## Losses

Every loss is a counter with a fixed reason. No label holds a tenant, a user,
or a key. The proxy also logs one warning for each loss class at most every
5 seconds. The warning names the reason and the counter. It never holds a
body, a tenant, or a credential.

### Dropped traces

A dropped trace is lost whole. The counter is
`llmproxy_trace_dropped_total{reason=...}`.

| Reason | Cause |
|---|---|
| `queue_full` | `max_queued_traces` captures were already in flight or queued. |
| `memory_budget` | The request body did not fit in `max_memory_bytes`. |
| `emergency_disabled` | The emergency switch closed. This includes captures that were in flight or queued at the time. |
| `unsupported_protocol` | The request was an upgrade, such as a WebSocket. |
| `exporter_failed` | The exporter thread stopped, or the proxy could not hand over the trace. |
| `abandoned` | The request ended without a normal finish, for example after a panic. |
| `write_error` | A segment could not be written or opened. The proxy deletes it. It counts every line in it, and the failing line. |
| `upload_backlog` | The proxy dropped an unsent segment at `max_disk_bytes`. |
| `shutdown` | Traces were still queued when the shutdown time ended. |

### Partial reasons

A partial trace is written. The line has `capture.state` of `partial` and the
reasons in `capture.reasons`. The counter is
`llmproxy_trace_partial_total{reason=...}`, one for each reason of each
trace. You decide whether to train on a partial trace.

| Reason | Cause |
|---|---|
| `request_over_cap` | The request body is over `max_request_body_bytes`. The line keeps the first bytes. |
| `response_over_cap` | The response body is over `max_response_body_bytes`. The line keeps the first bytes. |
| `memory_budget` | The response did not fit in `max_memory_bytes`. The line keeps what was copied. |
| `stream_unterminated` | The stream ended without its final event. |
| `unsupported_dialect` | A stream of a dialect that the proxy does not reassemble. |
| `unsupported_shape` | The events do not match a known shape. |
| `malformed_stream` | An event had `data` that is not JSON. Reassembly continues. |
| `request_not_json` | The request body is complete and is not JSON. |
| `response_not_json` | A response that is not a stream is complete and is not JSON. |
| `content_encoding` | The body has an encoding other than `gzip`, `deflate`, or identity, or it did not inflate. |

### Lost segments, expired segments, and upload failures

| Counter | Reasons | Meaning |
|---|---|---|
| `llmproxy_trace_segments_lost_total` | `upload_backlog`, `unsealed_at_start`, `write_error` | A segment never reached its destination. |
| `llmproxy_trace_segments_expired_total` | `age`, `size` | The directory retention that you set removed a segment. |
| `llmproxy_trace_upload_failures_total` | `connect`, `timeout`, `status_4xx`, `status_5xx`, `io` | One failed upload attempt. The proxy retries it. |

### Metrics

Each series below is registered at start, so an idle exporter shows zeros.
The names are in `crates/proxy-observability/src/stats.rs`. On
`/stats/prometheus`, the proxy adds the prefix `envoy_`. For example,
`llmproxy_trace_dropped_total` is `envoy_llmproxy_trace_dropped_total`. These
metrics are not in `/stats`. See
[Metrics and /stats](../metrics-and-stats/).

| Metric | Type | Labels | Counts |
|---|---|---|---|
| `llmproxy_trace_captured_total` | counter | none | Captures handed to the exporter. |
| `llmproxy_trace_dropped_total` | counter | `reason` | Whole traces lost. |
| `llmproxy_trace_written_total` | counter | `capture` (`complete`, `partial`) | Lines written. |
| `llmproxy_trace_partial_total` | counter | `reason` | Each partial reason on a written line. |
| `llmproxy_trace_segments_sealed_total` | counter | `reason` | Segments sealed. |
| `llmproxy_trace_segments_uploaded_total` | counter | none | Segments that the store accepted and the proxy deleted. |
| `llmproxy_trace_segments_lost_total` | counter | `reason` | Segments lost. |
| `llmproxy_trace_segments_expired_total` | counter | `reason` | Segments removed by directory retention. |
| `llmproxy_trace_upload_failures_total` | counter | `reason` | Failed upload attempts. |
| `llmproxy_trace_consent_stale_total` | counter | none | JWT requests with an opt-in withheld because the policy snapshot was stale. |
| `llmproxy_trace_memory_bytes` | gauge | none | Body bytes held by captures in flight or queued. |
| `llmproxy_trace_slots` | gauge | none | Captures in flight or queued. |
| `llmproxy_trace_disk_bytes` | gauge | none | Segment bytes on disk, open and sealed. |
| `llmproxy_trace_exporter_up` | gauge | none | `1` while the exporter runs. `0` after it stops. |
| `llmproxy_trace_capture_disabled` | gauge | none | `1` while the emergency switch is closed. The exporter updates it once a second. |

To read the state and generation of the emergency switch, use
`GET /traces/capture`.

Alert on a rising `llmproxy_trace_dropped_total`, on a rising
`llmproxy_trace_segments_lost_total`, and on `llmproxy_trace_exporter_up` at
`0`.

## Remove duplicates

Upload is at least once. A crash between an upload and the local delete
uploads the same segment again. The key is the same, so the new object
replaces the old one with the same bytes. The proxy does not remove
duplicates. Remove them in your consumer with the `event_id` field.

`event_id` comes from an internal random request id. It never comes from the
`x-request-id` of the caller.

## Emergency switch

Use the emergency switch to stop all capture at once. It needs the admin
token. Without `LLMPROXY_ADMIN_TOKEN`, the admin server refuses the call with
`403`: `admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is
not set`. In that case, the other levers are to remove the `traces` block and
restart the proxy, or to opt the tenant out.

1. Read the state and the generation.

   ```bash
   curl http://$ADMIN_ADDR/traces/capture \
     -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN"
   ```

   The answer is `{"disabled":false,"generation":0}`.

2. Disable capture. Send the generation from step 1.

   ```bash
   curl -X POST http://$ADMIN_ADDR/traces/capture \
     -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
     -d '{"disabled":true,"expected_generation":0}'
   ```

   The answer is `{"disabled":true,"generation":1,"persisted":true}`.

To enable capture again, send `{"disabled":false,"expected_generation":1}`.

The switch works like this
(`crates/proxy-observability/src/traces/gate.rs`):

- It is compare-and-set. A stale generation gives `409` with
  `{"error":"stale_generation","generation":N}`, and changes nothing.
- A disable takes effect at once for new requests. It also discards captures
  in flight and queued. Each is counted in
  `dropped{reason="emergency_disabled"}`. Lines already in segments stay.
  Delete them yourself if you must.
- A disable is saved in `<directory>/.capture-disabled` (`0600`). It survives
  a restart. At start, the proxy logs `trace capture starts DISABLED`.
- A disable always takes effect. If the proxy cannot write the file, the
  answer has `"persisted":false`. A restart then opens capture again.
- An enable removes the file first. If it cannot, the proxy answers `500`
  with `cannot update <path>: <reason>`, and capture stays closed.
- Without a `traces` block, both calls give `404`.

`the_emergency_switch_stops_capture` in
`crates/proxy/tests/trace_export_e2e.rs` tests this against the real binary.

## Load the files into a warehouse

These three examples are not tested. They show the idea. Check the syntax
for your warehouse version. In each, the partition values `tenant` and `date`
come from the key. The tenant value is percent-encoded.

**Snowflake (Snowpipe).** Create an external stage over the prefix, then
load the gzip JSON.

```sql
CREATE STAGE llmproxy_traces
  URL = 's3://my-traces/llmproxy/'
  STORAGE_INTEGRATION = my_integration
  FILE_FORMAT = (TYPE = JSON COMPRESSION = GZIP);

CREATE TABLE traces (line VARIANT);

CREATE PIPE traces_pipe AUTO_INGEST = TRUE AS
  COPY INTO traces FROM @llmproxy_traces
  PATTERN = '.*[.]jsonl[.]gz';
```

**BigQuery.** An external table reads `gs://` only. The proxy uploads with
the S3 protocol. Use an S3-compatible endpoint of Google Cloud Storage, or
copy the objects. Neither path is tested.

```sql
CREATE EXTERNAL TABLE traces.lines
WITH PARTITION COLUMNS (tenant STRING, date STRING)
OPTIONS (
  format = 'NEWLINE_DELIMITED_JSON',
  uris = ['gs://my-traces/llmproxy/*'],
  hive_partition_uri_prefix = 'gs://my-traces/llmproxy',
  require_hive_partition_filter = false
);
```

**ClickHouse.** Use the `s3()` table function with a glob.

```sql
SELECT
  JSONExtractString(line, 'event_id') AS event_id,
  JSONExtractString(line, 'capture', 'state') AS state
FROM s3(
  'https://my-traces.s3.eu-west-1.amazonaws.com/llmproxy/tenant=*/date=*/*.jsonl.gz',
  'JSONAsString', 'line String')
GROUP BY event_id, state;
```

In each case, remove duplicates on `event_id`.

## Delete data

Deletion works for one tenant prefix. To delete a tenant, delete
`tenant=<t>/` in the bucket or the directory. Deleting the traces of one
user from inside a segment is not supported.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| The proxy does not start. The message has `requires auth`. | `observability.traces` without `auth`. | Add the `auth` block. |
| The proxy does not start. The message has `trace export requires a node id`. | No `--service-node`. | Start with `--service-node <unique name>`. |
| The proxy does not start. The message has `another process holds`. | Another process uses the directory. | Give each process its own directory. |
| The load error names `max_disk_bytes` and a minimum. | The disk cap is under 2 x `max_open_segments` x `segment_max_bytes`. | Raise `max_disk_bytes`, or lower the other two. |
| `PUT /tenants/{id}/trace_export` gives `404`. | The tenant does not exist. | Create it with `POST /tenants`. |
| `PUT ...` or `POST /traces/capture` gives `403`. | `LLMPROXY_ADMIN_TOKEN` is not set. | Set it and restart. |
| A tenant is opted in and no files appear. | Segments seal after `segment_max_age`. Or the opt-in reset after a restart. Or the gate is closed. | Wait, check `GET /tenants/{id}/trace_export`, and check `GET /traces/capture`. |
| Many small objects in the bucket. | More active tenants than `max_open_segments`. | Raise `max_open_segments`. |
| `llmproxy_trace_upload_failures_total` rises. | The store refuses or is not reachable. | Check the `reason` label, the credentials, the bucket policy, and the endpoint. |

## Not available

- Metadata export of traces to OTLP or Kafka.
- Capture of upstream requests and responses.
- Redaction of bodies.
- Deletion of one user inside a segment.
- Credentials from an instance role.
- Direct writes to a warehouse.
