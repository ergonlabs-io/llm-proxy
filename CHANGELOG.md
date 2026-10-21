# Changelog

All notable changes to this project are recorded here. Releases and their ship gates are
defined in [`internal-docs/MILESTONES.md`](internal-docs/MILESTONES.md); open work packages are tracked in
[`internal-docs/boards/backlog.yaml`](internal-docs/boards/backlog.yaml). This file records _what shipped_, not
what is planned.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project is pre-1.0: the config surface is not yet stable, and the `llmproxy` dialect's
`version: 0` schema is frozen only from its first release onward.

## [Unreleased]

### Breaking

- The capture agent is retired. Use [trace export](docs/site/src/content/docs/observability/trace-export.md)
  for bodies and `--request-records-file` for request metadata records.
  - The `llm-capture-agent` binary is no longer in the release tarballs or
    installed by `install.sh`.
  - These flags are removed: `--request-records-agent`,
    `--request-records-agent-uid`, `--request-records-agent-node`,
    `--request-records-producer`, and the hidden
    `--capture-spool-poll-interval-ms`. `--request-records-file` and
    `--request-record-max-attempts` stay.
  - A bootstrap that sets `node.metadata["io.llmproxy.capture"]` now fails to
    load with that path in the error. Remove the key.
  - The `/capture/spool/stats` and `/capture/spool/records` admin endpoints and
    the Admin UI Capture tab are removed. `/traces/capture` stays.
  - The `llmproxy_capture_*` metrics and `llmproxy_metadata_durable` are
    removed.
  - `capture_policy_version` stays in request records, ledger entries and
    trace lines, so no schema version changes. It is always `null`.
  - The `proxy-capture-spool` crate stays, with its on-disk format unchanged:
    the billing ledger is built on it.

### Added

- JWT claims can set chargeback tags. `auth.jwt[].claim_tags` (Envoy mode:
  `JwtProvider.claim_tags`) maps a verified claim to a tag key, for example
  `{ claim: department, tag: team }`, so the identity provider sets a JWT
  caller's attribution, not the client. The `auth.chargeback_tags` allow-list
  and caps apply unchanged, and the `x-cost-tags` header cannot set a mapped
  tag. Each tag must be allow-listed, or the config does not load.
- `llmproxy_chargeback_tags_dropped_total` has a sixth `reason`,
  `claim_missing`, for a mapped claim that is not in the token. A claim that is
  not a string of tag value characters counts as `malformed`. Neither refuses
  the request.

- **Realtime (WebSocket) sessions (WP-37, ADR-0015).** `realtime: { enabled: true }`
  in the `--config` dialect (Envoy mode: `upgrade_configs` with `upgrade_type:
  websocket`) proxies a WebSocket on a path ending `/realtime` as one metered
  session. Auth, model access, `limits` and spend budgets decide at upgrade time,
  before the provider is dialled; a refusal is an HTTP status. The model is the
  `model` query parameter, rewritten to the provider's upstream model.
  `limits[].concurrent_sessions` counts a session for its whole life. Usage is
  summed from each `response.done` event (text, cached and audio tokens), priced at
  the rate card's token and audio rates for the provider dialled, and charged once
  when the session closes; a session cut early is recorded partial and charged what
  it reported. Each session is one access-log line, request record and ledger entry,
  with endpoint `realtime`. A response with no readable usage is counted in
  `llmproxy_realtime_usage_missing_total{reason}` and warned about. The proxy removes
  the client's `Sec-WebSocket-Extensions` offer from a realtime session so its frames
  stay readable. On drain each WebSocket session gets a Close frame with code 1001.

- `make smoke-live` runs live smoke tests against real providers: OpenRouter
  on a free model (non-streaming, streaming, and a bad key that must return
  the provider's 401), Vertex AI, Amazon Bedrock, OpenAI and Anthropic. Each
  checks the status, the content, and the access-log line's provider and
  extracted usage. A provider with no credentials is skipped by name
  (`LIVE-SKIP`); `LIVE_SMOKE_STRICT=1` makes that a failure. The workflow
  `.github/workflows/live-smoke.yml` runs the target weekly and on demand,
  never on pull requests. See `testing/diffrig/README.md`.

### Changed

- A JWT caller (`auth.jwt`, or `jwt_providers` in Envoy mode) whose tenant
  stored its own provider credentials is now sent upstream with that tenant's
  credential, and its spend is tenant-scoped, exactly as for a virtual key of
  the same tenant. Before, it always used the operator's provider key and was
  charged as platform spend. A tenant with no stored credential is unchanged.
  The load warning for `auth.jwt` with `auth.tenant_credentials` is removed
  (ADR-0014 decision 2, amended).
- When the policy snapshot is older than `auth.max_policy_staleness`, a JWT
  request of a tenant that holds stored provider credentials gets `503`
  (`auth_policy_stale`), as that tenant's virtual keys do. JWT requests of
  other tenants are admitted as before.

- **The HTTP filter chain runs on upgraded streams (WP-131, envoy-semantics.md
  S10.2).** An upgrade's post-`101` upstream bytes pass through the encode filter
  chain, and the stream ends when the tunnel closes: the access log, request record
  and ledger entry of an upgraded stream are written at its close, not at the `101`,
  and `downstream_rq_active` counts it until then, as Envoy does. Client-to-upstream
  bytes still go straight through (`internal-docs/envoy-divergences.md` row 44). A
  listener with an enabled upgrade type now refuses, at load, an HTTP filter that can
  buffer response bytes.

## [0.6.1] - 2026-10-20

### Fixed

- A billing ledger at its `max_disk_bytes` cap could stay closed after the
  consumer acknowledged every entry. One group commit can be larger than the
  spool holds at its cap. That commit was refused and retried whole after each
  acknowledgement, so admissions never resumed and the held entries were lost
  at shutdown. The writer now commits in chunks of at most 1/16 of
  `max_disk_bytes`. The risk was highest at small caps with large entries.
- One billing-ledger entry too large for the spool at its cap had the same
  effect, even when every other entry was acknowledged. An entry larger than
  1/16 of `max_disk_bytes` (128 KiB at the 2 MiB minimum) is now not written.
  It is counted in `llmproxy_ledger_entries_lost_total{reason="oversize"}`, as
  entries over 1 MiB already were. The error log for these entries now repeats
  at most once every 5 seconds.

## [0.6.0] - 2026-10-20

### Breaking

- Billing-ledger entries are now `schema_version: 2`, which adds
  `record.tags`. Nothing else in the entry changes, and version-1 entries
  already in the spool are still returned as version 1. Update a consumer
  that accepts only version 1.
- A key with chargeback tags is stored as auth-store row version 3. A build
  from before this release refuses to load a store that holds one, instead of
  dropping the tags. Clear key tags (`PUT /keys/{id}/tags` with `{"tags":{}}`)
  before a downgrade.

- The OpenTelemetry semantic-conventions version moves from 1.27.0 to 1.41.0,
  the last release that holds the GenAI conventions in the core repository.
  On `gen_ai.server.time_to_first_token` and
  `gen_ai.server.time_per_output_token`, the label `gen_ai.system` is now
  `gen_ai.provider.name` (`gen_ai_provider_name` in `/stats/prometheus`). The
  values (`openai`, `anthropic`) do not change. Update dashboards and alerts
  that select on `gen_ai.system`.

### Added

- `make bench-added-latency` measures the latency the proxy adds to one
  request over a direct call to the mock upstream: p50 and p99 for direct,
  proxy with controls off, and proxy with each control group added in turn
  (auth, limits, spend, ledger), in alternated rounds, compared on minimums.
  It fails a run whose controls did not engage. README "Measured capacity"
  has a new "Added latency with controls on" table, measured under load:
  0.23 ms p50 and 0.97 ms p99 added with controls on. Method and configs:
  `internal-docs/capacity/added-latency.md` (WP-116).

- Image generation is metered under a spend budget (ADR-0010 phase 2, WP-124).
  `POST .../images/generations` is no longer refused with
  `endpoint_not_metered` under a tenant or key budget; it is charged at the
  rate card of the provider that served it. A token limit still refuses it.
  - A rate-card entry has a `basis`: `tokens` (the default, the behaviour
    before) or `images`. An `images` entry prices the images the response
    returned with `image_prices` rows (`size`, `quality`,
    `nanodollars_per_image`); the most specific matching row wins, and two
    rows that can match the same request at the same specificity are a load
    error.
  - A tier can set `image_input_nanodollars_per_token`,
    `image_output_nanodollars_per_token`, `audio_input_nanodollars_per_token`
    and `audio_output_nanodollars_per_token`, on every tier of an entry or on
    none. Image and audio tokens are then charged at their own rate. Without
    one they are charged at the text rate, as before, and counted in the new
    `llmproxy_usage_underpriced_modality_requests_total`; under a budget the
    spend filter also warns once per model.
  - Image responses are read by a bounded structural scanner, so a
    multi-megabyte base64 body is counted without being held. A cut image
    response is charged the images that closed and the tokens reported, never
    an estimate from its byte count. An image whose card has no matching row
    is unpriced: charged $0 and warned about, like an unpriced model.
  - Request records and ledger entries carry `endpoint`, `price_basis`, the
    image and audio token subsets, `images`, `image_size` and
    `image_quality` (optional fields; schema versions stay 1). New access-log
    operators `%LLM_IMAGES%`, `%LLM_INPUT_CHARACTERS%`, `%LLM_AUDIO_MS%`,
    `%LLM_INPUT_IMAGE_TOKENS%`, `%LLM_OUTPUT_IMAGE_TOKENS%`,
    `%LLM_INPUT_AUDIO_TOKENS%`, `%LLM_OUTPUT_AUDIO_TOKENS%` and
    `%LLM_PRICE_BASIS%`, with matching `llm_*` keys in the `--config` JSON
    access log.
  - Upgrade note: a card that uses `basis`, `image_prices` or a modality rate
    is stored at rate-card schema version 2, which an older replica ignores
    (it keeps its last card). Upgrade every replica before publishing such a
    card with `PUT /pricing`. A card that uses none of them keeps its version
    and its charges.
- Speech, transcription, translation and image edits are metered under a
  spend budget (ADR-0010 phase 3, WP-125). They are no longer refused with
  `endpoint_not_metered` under a tenant or key budget when their cost can be
  counted; they are charged at the rate card of the provider that served
  them. A token limit still refuses them all. Batch stays refused.
  - Two more rate-card bases. `characters` prices the characters of a speech
    request's `input` (`nanodollars_per_character`): Unicode code points after
    JSON unescaping, charged only for a 2xx response, rounded up to a whole
    micro-USD. `audio_seconds` prices the duration a transcription or
    translation response reports (`nanodollars_per_second`): `usage.seconds`
    of a `duration` usage, `usage.prompt_audio_seconds`, or the `verbose_json`
    `duration`, per millisecond, rounded up to a whole nanodollar. Image edits
    use the `images` and `tokens` bases like generations.
  - `multipart/form-data` requests (transcription, translation, image edits)
    are routed on their `model` field, authorized against model policies, and
    have a provider's model mapping written into that field. The scanner reads
    the whole buffered form, keeps only the text fields it needs, and treats a
    field sent twice, as a file, or with a transfer encoding as not sent. A
    provider with a `request_fields` policy still refuses a form.
  - Under a budget, a request whose shape cannot be counted is refused with
    `403` `endpoint_not_metered` once its body is read: a form or speech body
    with no provable `model`, speech with no string `input`, a transcription
    whose `response_format` is `text`, `srt` or `vtt`, and a translation that
    is not `verbose_json`.
  - Speech, transcription and image-edit stream usage is read from any event
    that carries it (`speech.audio.done`, `transcript.text.done`), and image
    edit streams count `image_edit.completed` events.
  - `examples/llmproxy-media.yaml` is a media rate card. It marks three
    provider facts as assumptions until a recorded response pins them: the
    character rule, `speech.audio.done` usage, and the cached image rate.
  - New fuzz target `multipart_scan`. The scheduled fuzz workflow now also runs
    `media_scan`, which WP-124 added but did not schedule.
  - Upgrade note: a card that uses `characters` or `audio_seconds` is stored at
    rate-card schema version 2, like the other media fields. A card that uses
    none of them keeps its version and its charges.
- Chargeback tags (WP-117): operator allow-listed `key=value` tags on usage
  records (`tags`) and billing-ledger entries (`record.tags`), to attribute
  spend to a project, team or cost centre. Configure them with
  `auth.chargeback_tags` (`allowed`, optional per-key `values`, `max_tags`,
  `max_value_bytes`, `from_header`); Envoy mode has the same fields on
  `llmproxy.auth` (`Authentication.chargeback_tags`). Tags come from key
  metadata, set with `POST /keys` (`tags`), the new `PUT /keys/{id}/tags`, or
  `auth.keys[].tags`, and, when `from_header: true`, from the `x-cost-tags`
  request header, which is then removed before the request goes upstream. A
  tag key set by key metadata always beats the header. JWT callers get header
  tags only. Dropped tags are counted in
  `llmproxy_chargeback_tags_dropped_total{reason}`; a malformed header never
  fails the request; tag values are never metric labels. `GET /keys` and
  `GET /keys/{id}/spend` show a key's tags. There is no tag budget.

- The OpenTelemetry GenAI client metrics `gen_ai.client.token.usage`
  (histogram, `{token}`, labelled by `gen_ai.token.type`) and
  `gen_ai.client.operation.duration` (histogram, seconds), for successful LLM
  requests with a known requested model. Their `input` includes cached tokens
  and cache writes, as OpenTelemetry defines it, so on a request with cached
  tokens it is larger than the `input` of `llm.client.token.usage`, which does
  not change. The `gen_ai.request.model` label has the same 1,000-series cap as
  the latency histograms.
- The server span of an LLM request carries `gen_ai.operation.name`,
  `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`,
  `gen_ai.response.id`, and the integer token counts
  `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
  `gen_ai.usage.cache_read.input_tokens` and
  `gen_ai.usage.cache_creation.input_tokens`, where the proxy knows them.
- JWT/OIDC authentication in the config file (ADR-0014). The new `auth.jwt`
  list sets an issuer, an audience, a key source (`jwks.discovery_url` or
  static `jwks.keys`), the claim and value map that select the tenant, and the
  claim that names the user. Each entry becomes one Envoy-mode
  `jwt_providers` entry, so verification is unchanged: RS256 only, and an
  expired, wrongly signed, wrong-issuer, wrong-audience or unmapped token gets
  `401`. A token gets no models from its claims. Its tenant gets the model
  policy, budget and limits set through the admin API, so a mapped tenant with
  no stored policy gets `403`. `issuer`, `audience`, `tenant.values` and
  `user.claim` are required, and a tenant named `default` or containing `:` is
  a load error. JWT callers always use the operator's provider keys; the proxy
  warns when `auth.tenant_credentials` is also set.
- Body-aware request guardrails: the dialect's top-level `guardrails` block
  (Envoy mode: the `llmproxy.guardrail` filter) sends each request body, with
  its tenant and its requested and resolved model, to an external HTTP check
  before any provider is dialled. A check that answers `deny` refuses the
  request with `403` and the check's reason (response-code detail
  `guardrail_denied`); the request is not dialled, not charged, not counted
  against a limit, and gets no ledger entry. `default` is required and
  `tenants` (which requires `auth`) replaces it per tenant. Each check sets
  `failure_mode` with no default: `closed` refuses an error or timeout with
  `503` and a body over `max_body_bytes` with `413`; `open` admits them,
  counts each as `failure_mode_allowed`, and warns at most once a minute
  naming only the check's host. Only authenticated, model-authorized requests
  are sent, and the check sees every prompt it is asked about. Outcomes are
  counted in `llmproxy_guardrail_checks_total{scope, outcome}` and logged by
  the new `%LLM_GUARDRAIL%` access-log operator, which the dialect's default
  formats now carry. The check only allows or denies; it never changes the
  request.

- Weighted selection among a `models` alias's providers. Set
  `models.<name>.providers[i].weight` on every entry (object form) and each
  request starts at a provider picked in proportion to weight; the other
  entries stay its fallbacks in list order, so failover, credentials, upstream
  model IDs and the rate card follow the provider actually dialled. `0` makes
  an entry fallback-only. The pick is random per request, the same on every
  worker, and not shared across replicas. It lowers to Envoy
  `weighted_clusters` over one aggregate per weighted provider. Weighting
  never changes the model; cost-aware selection is still not supported.
  Aliases without weights lower exactly as before.
- `providers.<name>.outlier_detection` (`consecutive_5xx`,
  `base_ejection_time`, `max_ejection_time`): passive health checking of a
  provider. An ejected provider gets no requests from a `models` alias while
  another of its providers is not ejected, and gets them again when the
  ejection ends.

### Security

- Spend budgets and token limits no longer let images, audio, batches and
  files through for free (ADR-0010 phase 1). A budget or token limit that
  applies to a request now refuses every endpoint whose cost the proxy
  cannot count with `403` and response-code detail `endpoint_not_metered`,
  before the provider is dialled. Before, these requests were served and
  charged $0, also when the client added a `"model"` field to a batch body.
  Each refusal increments
  `llmproxy_unmetered_endpoint_refused_total{endpoint, control}`. Requests
  that no budget or limit applies to are unchanged and log nothing.
  `GET .../models`, `GET .../usage` and `POST .../messages/count_tokens`
  pass and no longer log a missing-usage warning under a budget or limit;
  neither does a request that reached no provider, such as the synthetic
  `404` for an unknown model.
  Retrievals of stored objects, such as `GET /v1/batches/{id}` and
  `GET /v1/responses/{id}`, are refused under a budget or limit too.
- Tenants can no longer reach each other's provider files and batches
  (ADR-0012). Every tenant uses the proxy's one provider account, so file and
  batch IDs share one namespace; before, tenant B could get, read, cancel and
  delete tenant A's file or batch, and list both. The new
  `llmproxy.object_ownership` filter records the tenant that created each
  object in `auth.store` and answers `404` before dialling when a request
  names an object, by path or by a `*_file_id` body member, that the caller's
  tenant does not own or that no tenant owns. Listing `/v1/files`,
  `/v1/batches` and `/v1/messages/batches` is refused. If the store cannot
  answer for an owner the proxy has not cached, the request gets `503`
  (`object_owner_unavailable`). The dialect turns it on with `auth`;
  `auth.enforce.object_ownership: false` turns it off with a load warning.
  **Upgrade note:** objects created before this release have no owner and
  get `404` until assigned with `PUT /tenants/{id}/objects/{object_id}`, and
  with `auth.store: in_memory` owners are lost on restart.
- The `--config` access-log formats gain `response_code_details`
  (`%RESPONSE_CODE_DETAILS%`), so a local refusal says why.

### Changed

- **Behavior change:** an aggregate cluster now passes over a member none of
  whose hosts is healthy (ejected by outlier detection or failing active
  health checks) while a later member has a healthy host, as Envoy does.
  Before, such a member's own panic pick kept receiving requests. With every
  member unhealthy, the chain runs in order as before. This affects
  bootstrap configurations whose aggregate members set `outlier_detection` or
  `health_checks`; `--config` providers had neither until this release.
- **Behavior change:** when a provider's credential cannot be applied (no
  unexpired minted OAuth2 token, a failed Bedrock signature, or another
  credential error), the request now moves to the next provider in its
  fallback chain instead of getting a local `503`. Nothing is sent to the
  failed provider, the fallback request carries only the fallback's
  credential, and the request is charged at the fallback's rate card. The
  move does not use a retry. A request with no next provider still gets the
  `503`. `llmproxy_provider_credential_requests_total` gains the outcomes
  `unavailable_failover`, `failed_failover` and `failed` (before, only
  `unavailable` was counted), and each failure logs a warning naming the
  provider's cluster, at most once a minute per cluster on each worker.
  Alert on the `_failover` outcomes: the client sees no error when a broken
  key sits behind a healthy fallback. Upgrade (WebSocket) requests do not
  fail over. See `internal-docs/envoy-divergences.md` row 43.
- **Behavior change:** request heads are now limited to 60 KiB and 100
  headers, Envoy's defaults. On HTTP/1 a larger head gets `431` and closes
  the connection before any filter runs; before, only hyper's own limits
  applied (about 408 KiB and 100 headers). On HTTP/2, as in Envoy, the
  decoded header list (name plus value per field, pseudo-headers included)
  is measured and an over-limit stream is reset with `INTERNAL_ERROR` while
  the connection stays up; before, hyper's 16 KiB default applied and the
  count was unlimited. Envoy mode maps HCM `max_request_headers_kb` and
  `common_http_protocol_options.max_headers_count`, which were refused at
  load; the dialect adds `listen.max_request_headers_kb` and
  `max_request_headers_count`. Remaining differences from Envoy are in
  `internal-docs/envoy-divergences.md`.
- **Behavior change:** a config reload (SIGHUP) or xDS listener update that
  changes `auth.hmac_secret` / `auth.hmac_secret_file` contents, `auth.keys`,
  `auth.store`, the policy poll interval or `auth.tenant_credentials` is now
  refused whole and names the field; the previous config keeps serving and
  a restart applies the change. Before, a changed secret was taken by the
  request authenticator but not by the control plane, so every key got `401`
  after a reload that logged success, and edits to `auth.keys` (including a
  removed or revoked key) were ignored silently. An xDS update with such a
  change is NACKed. A reload that changes `observability.tracing` or
  `observability.metrics` is refused too; both start once at boot and were
  ignored. Provider `api_key_file` and credential files are still re-read on
  each reload.

- **Behavior change:** an access-log `%START_TIME(fmt)%` pattern that chrono
  cannot format (an unknown specifier, or abseil extensions such as Envoy's
  `%E3S`) is now a config load error, or a NACK over xDS, that names the
  pattern. Before, it loaded and then logged a timestamp cut off at the bad
  specifier on every request. `internal-docs/envoy-divergences.md` row 42.

### Fixed

- Billing ledger: when an acknowledgement at the disk cap could not put the
  spool's acknowledgement reserve back, admissions stayed closed with nothing
  left to acknowledge, so the documented "acknowledge until `admitting` is
  `true`" loop never ended and a restart was needed. The same happened when
  the retried commit of held entries was refused once more after everything
  was acknowledged. Repeating the last acknowledgement now puts the reserve
  back and lets the held commit try the disk again.

- Route header matchers (`string_match` and `safe_regex`) now match header
  values that are UTF-8 beyond ASCII. Before, such a value never matched, so a
  request whose model name has a non-ASCII character (the dialect publishes it
  on `x-llmproxy-model`) missed its route and fell through to the next one.

## [0.5.0] - 2026-10-18

### Added

- Minted Vertex access tokens: `providers.<name>.oauth2_jwt_bearer` (Envoy
  mode: `scheme: oauth2-jwt-bearer` in `io.llmproxy.provider_auth`) makes the
  provider cluster mint its OAuth2 access token with the JWT-bearer grant
  (RFC 7523) from an RSA service-account key, and mint the next one
  `refresh_before` (default 5m) its expiry. Workers never call the token
  endpoint. The key file is read and checked at every load; a bad key is a
  load error naming its path, and `SIGHUP` rotates it. With no unexpired
  token, a request gets a local `503 provider token unavailable`, is not
  failed over, and is counted in `llmproxy_provider_credential_requests_total`.
  Failed mints retry with backoff and keep the last token until it expires.
  The configured `access_token` modes are unchanged.
- Trace export (ADR-0008): the dialect's `observability.traces` block (Envoy
  mode: `node.metadata["io.llmproxy.traces"]`, requires `auth` and
  `--service-node`) writes the request body as received and the response body
  as delivered, one JSON line per request, to gzip or zstd segments under
  `tenant=<t>/date=<d>/`. Off unless the operator sets the block and the
  tenant opts in with `PUT /tenants/{id}/trace_export`; there is no
  redaction, and the opt-in is consent to raw capture. SSE responses are
  reassembled for `openai` (chat, completions, Responses) and `anthropic`;
  other streams export as delivered bytes marked partial. An optional `s3`
  destination uploads sealed segments with static keys and drops the oldest
  unsent segment at `max_disk_bytes`; only a local test double was tested, not
  AWS, GCS, R2 or MinIO. `POST /traces/capture` is a persisted emergency
  switch (`GET` reads it). Every loss is counted by reason in
  `llmproxy_trace_*` metrics. Best effort, for analytics, never billing.
  See `docs/site/src/content/docs/observability/trace-export.md`.
- Request records and the `%LLM_USER_ID%` access-log operator now name the
  authenticated user. A virtual key is its user, so the value is the key id.
  A JWT names a user only when `subject_claim` is set; the value is then the
  issuer- and tenant-scoped subject, the same string as the key id. Without a
  subject claim the value stays null. A `user` field in the request body is
  never used. No metric carries the user as a label.
- Billing ledger (ADR-0009): the dialect's top-level `ledger` block (Envoy
  mode: `node.metadata["io.llmproxy.ledger"]`) writes one encrypted entry for
  every request dialled to a provider to a local spool, committed in groups of
  `group_commit_max_entries` or every `group_commit_interval` (default 50ms).
  Each request reserves a ledger slot before it is dialled. With no slot (all
  `max_reservations` held, the writer failed, or the spool at
  `max_disk_bytes`), `on_unavailable: reject` (the default) answers 503 naming
  the reason, and `admit` serves the request without an entry, counted in
  `llmproxy_ledger_unledgered_total` and warned about at most once every 5
  seconds. The ledger needs `--service-node`, which becomes every entry's
  `instance_id`; each start opens a later `epoch`, and `seq` is gapless per
  epoch. A crash loses every entry not yet committed: normally about the
  last group-commit interval, but at the disk cap every entry held in memory,
  up to `max_reservations`. Committed
  entries are never evicted; only an acknowledgement frees space. A reload
  that changes the ledger is refused. New counters: `llmproxy_ledger_rejected_total`,
  `llmproxy_ledger_unledgered_total`, `llmproxy_ledger_entries_committed_total`,
  `llmproxy_ledger_entries_lost_total`.
- Billing ledger delivery (ADR-0009 decisions 7 and 8). `GET
  /ledger/entries?after=<cursor>&limit=<1..=1000>` returns committed entries
  only, in order, each with its `cursor`, `instance_id`, `epoch` and `seq`.
  `POST /ledger/ack?through=<cursor>` removes every entry up to the cursor
  from the spool. Both need the admin bearer token and refuse unknown or
  malformed parameters with 400. The cursor is the spool's position: unlike
  `seq` it keeps increasing across restarts. Delivery is at least once, so
  deduplicate on `event_id`. When the spool is at `max_disk_bytes`, an
  acknowledgement frees space, the entries held at the cap are written, and
  requests are admitted again without a restart; the answer's `admitting`
  is `false` while the held entries still do not fit, so keep pulling and
  acknowledging. New reconciliation counters:
  `llmproxy_spend_charged_micro_usd_total` (micro-USD the spend filter
  charged) and `llmproxy_ledger_spend_written_micro_usd_total` (micro-USD of
  spend charges in committed entries). They are equal unless entries were
  lost (`llmproxy_ledger_entries_lost_total`) or served under `admit`.
- Billing ledger hardening (ADR-0009 hardening addendum). An
  acknowledgement of any committed range succeeds at `max_disk_bytes`: the
  spool keeps a reserve for acknowledgements and frees a large range in
  parts, so a consumer no longer retries shorter prefixes on `507`. A start
  that finds the previous epoch did not close (a crash, or a stop with
  uncommitted entries) logs an error and counts it in the new
  `llmproxy_ledger_unclean_epochs_total`, and `GET /ledger/entries` returns
  `epochs` with a `closed` flag for the last 64 epochs. Under
  `on_unavailable: reject` the ledger's 503 is now answered just before
  dialling, after every filter: a request without a valid key gets 401, not
  503, and only requests that would have been dialled count in
  `llmproxy_ledger_rejected_total`.
- User guide for the billing ledger: `limits-and-budgets/billing-ledger` in the
  docs site, and `examples/llmproxy-ledger.yaml`.

### Fixed

- The `--config` dialect no longer expands `${VAR}` references inside YAML
  comments. Before, a commented-out line such as
  `# api_key: ${OPENAI_API_KEY}` failed the load when the variable was unset.
  A `#` inside a quoted string or a block scalar is text, not a comment, so a
  reference after it is still expanded. An unset variable in a value still
  fails the load, and the error now names the field, for example
  `providers.openai.api_key`. The `llm-proxy init` starter config uses
  `${VAR}` placeholders in its commented provider examples.

### Internal

- The billing-ledger entry (ADR-0009) is built at stream end for every request
  dialled to an upstream: the terminal request record, the micro-USD the spend
  counters were charged (copied from the spend filter, or the list price rounded
  up the same way when no spend filter ran), the charged tenant and key scopes
  with their budget periods, the rate-card version, and a gapless per-instance
  sequence number. Requests refused before dialling get no entry. The ledger
  writer thread assigns the sequence numbers, so the request path takes no lock.

## [0.4.1] - 2026-10-17

### Removed

- **Breaking (Envoy mode):** the `pricing` field of `llmproxy.spend_limit`
  (`ClusterPricing`, `ModelPrice`). A config that still sets it fails to
  load, naming the field. Move the prices to the rate card: `pricing_json`
  on `llmproxy.filters.v0.Usage`, or `PUT /pricing`. The `--config` dialect
  never set this field and is not affected.

### Added

- The `%COMMON_DURATION(START:END[:PRECISION])%` access-log operator, as in
  Envoy v1.38. It gives the time between two of the twelve standard points
  of a request (`DS_RX_BEG` to `DS_TX_END`, including `US_CX_*`,
  `US_HS_END`, `US_TX_*` and `US_RX_*`), in `ms` (the default), `us` or `ns`.
  A point the request did not reach renders `-`. A request on a reused
  upstream connection repeats the connect points of that connection, as in
  Envoy. A name that is not a standard point is a config error; Envoy
  accepts it as a custom point (`internal-docs/envoy-divergences.md` #35).
- The `llmproxy` dialect's default access-log lines now carry the request
  phases, in microseconds: `timing_us="ds_rx=... pre_upstream=... us_tx=...
  us_wait=... resp_head=... ds_tx=..."` in the text format, and `ds_rx_us`
  ... `ds_tx_us` in the JSON format. `us_wait` is the provider's time to
  response headers. A new upstream connect is part of `pre_upstream`; there is
  no separate connect phase, because a reused connection repeats the connect
  time of the request that opened it. See "Request phases" in the access-log
  docs.

### Changed

- The rate card is the only price source for spend budgets. The spend
  filter no longer falls back to its own per-cluster price table, so every
  charge comes from one card, which replicas sharing a store also share.
- `PUT /pricing` with a `persistent` store now says that the card survives a
  restart but that other replicas do not read it. Only `auth.store: shared`
  shares a rate card across replicas; the docs and schema now say so, and the
  per-replica store warning names the rate card.
- A `SIGHUP` reload that changes `pricing` while a store holds a different
  card now logs a warning that the change was not applied (it was `info`).
- Access logs cost less CPU: about 0.11 ms less per non-streaming request
  with the `llmproxy` dialect's default JSON log, which now costs about
  0.06 ms (it was 0.15 ms). The rendered lines do not change. The log
  writer now batches lines and flushes every 100 ms, or sooner when 64 KiB
  are waiting, so a line can reach its file or stdout up to 100 ms after
  the response. Shutdown and a reopen still flush first.
- An HTTP/1.1 upstream connection is now reused after a response framed by
  `Content-Length`, including an empty one. Before, through a real client
  connection, only a chunked response returned its connection to the pool:
  every other HTTP/1.1 request to a provider opened a new TCP (and TLS)
  connection. A response the client abandons is still never reused.
- A policy load that finds the shared store empty after it held tenants or
  keys now logs an `error` line with the before and after counts and
  generation stamps, and increments
  `llmproxy_policy_store_emptied_total{scope}`. Before, the replica logged
  the empty load at `info` and every stored key got 401 with no other signal.
  A Redis restarted without persistence, or flushed, causes this; the shared
  Redis needs AOF or RDB persistence (see "The shared store needs
  persistence" in Running in production).

### Fixed

- Request records now carry `policy_generation`: the generation of the
  control-plane snapshot that verified the request's key. Before, the field
  was always null. It stays null for a request that `llmproxy.auth` did not
  authenticate with a virtual key, for example a JWT.
- A rate card in the store dated more than five minutes ahead of a replica's
  clock is no longer refused for good on that replica. The replica keeps its
  current card, logs a warning once, and installs the stored card on the first
  policy poll after its clock reaches the date. Before, it stayed on the old
  card until another write to the store.

## [0.4.0] - 2026-10-16

### Breaking

- `auth.store: shared` now requires a node id. In the dialect, pass
  `--service-node <name>` (the dialect has no node id field); in Envoy mode,
  pass `--service-node` or set the bootstrap `node.id`. Without one, the config
  is a load error at `auth.store.shared` (dialect) or
  `typed_config.store.shared` (Envoy mode). Use a name that is unique to the
  replica and stable across its restarts, such as the pod name. Before, each
  boot wrote under a new per-boot id, and the shared store kept that boot's
  dedup state; spend rows for periods that never end kept it permanently.

### Added

- Per-key model allow-lists. `PUT /keys/{id}/policy` (scoped form
  `PUT /chains/{stat_prefix}/keys/{id}/policy`) takes the body of
  `PUT /tenants/{id}/policy`. The effective models of a request are the tenant grant
  intersected with the key list: a key only narrows, a key with no policy keeps its
  tenant's grant, and `{"access":"all"}` returns a key to that grant. A refusal is the same
  `403 model_not_permitted`. The policy applies to the next request, survives a restart on
  the persistent store, and also narrows under `tenants_without_policy: allow`. The route
  answers `409 not_enforced` if no chain runs `llmproxy.model_authz`.
- Tenant and key rate limits. `PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits`
  (scoped forms under `/chains/{stat_prefix}/`) set `tokens_per_minute`,
  `requests_per_minute` and `concurrent_streams`; `{"limits": null}` clears them. A request
  must pass the tenant limits and the key limits, so a key only narrows its tenant. A
  refusal is `429` with `x-ratelimit-*` and `retry-after` headers and a body of
  `token budget exceeded`, `request rate exceeded` or `too many concurrent streams`.
  Limits apply to the next request and survive a restart on the persistent store. The
  routes answer `409 not_enforced` if no chain runs `llmproxy.token_limit`. `GET /keys`
  lists the limits of each key.
- `auth.enforce.limits` (default `true`): with `auth` set, the dialect adds
  `llmproxy.token_limit`, so tenant and key limits are enforced without a `limits:` entry.
  With `false` and no `limits:` entry the filter is omitted.
- Rate windows are aligned to the Unix epoch (a 60-second window starts on a whole
  minute), so every replica counts the same minute under the same name. The first window a
  caller sees can be shorter than the configured length. Token and request counts
  reconcile through `auth.store` about once a second, and a `shared` store shares them
  across replicas. The gauge
  `envoy_llmproxy_counter_reconciliation_age_seconds{seam}` on `/stats/prometheus` reports
  the age of the last reconcile for `rate_window` and `stream_lease`.
- `GET /v1/usage` now reports each tenant rule that has a `tokens_per_minute` limit, as a
  route named `*` (plus its model scope). With `auth.store: shared` it reads the fleet
  totals from the store off the worker, and a store error or a read past about 2 seconds
  answers `503 usage unavailable` with `retry-after: 1`.
- `GET /v1/models` is answered by the proxy and never forwarded. It lists the catalogue:
  each exact `routes[].model` and `models` key, without names that contain `*` and
  without `auto`. With `auth` and `auth.enforce.model_policy` on, it lists only the models
  that the tenant grant and the key policy both permit. Envoy mode: `ModelAuthz.model_catalog`.
- `/v1/embeddings` is metered on every cluster dialect. Usage reaches the access log
  (`gen_ai.operation.name=embeddings`), token limits, and tenant and key spend, priced at
  the rate card of the provider that served the request.
- Schema gate: `make schema-check`, part of `make ci`, validates every example dialect
  config against `schema/llmproxy-v0.schema.json` and checks that the schema and the
  parser agree on fields.
- Generated configuration reference: `make config-reference` regenerates
  `docs/site/src/content/docs/configuration/reference.md` from the schema.
  `make config-reference-check` fails if the committed copy is stale, and `make ci` runs it.
- A node id with `auth.store` set to `in_memory` or `persistent` now logs one
  warning per auth chain at startup: limits and budgets apply per replica, so N
  replicas admit up to N times each limit.
- `envoy_llmproxy_control_plane_store_info{scope,store,node_id}` (always 1)
  reports the store each auth chain uses and the replica's node id, so a fleet
  can be checked from metrics.

### Changed

- Concurrent-stream limits (`concurrent_sessions` in `limits:`, and
  `concurrent_streams` in tenant and key limits) now apply to the fleet when
  `auth.store` is `shared`. Each replica publishes its in-flight count to Redis
  once a second as a lease row with a 5-second TTL, so a replica that is killed
  releases its slots within 5 seconds. If Redis cannot be reached, the proxy
  keeps enforcing against the last fleet counts it read and logs one warning
  per chain per minute.
- Every `limits[]` field and bucket key of the dialect is now enforced:
  `tokens_per_minute`, `requests_per_minute`, `concurrent_sessions` and `models`, with the
  keys `global`, `client-ip`, `tenant` and `header:<name>`. The load-time "not enforced"
  warnings and the matching schema text are removed.
- `key: header:authorization` buckets on the hashed header value as written, also with
  `auth` set. A rule on it behind `auth`, which removes the verified header, counts one
  bucket per authenticated virtual key.
- A chain that enforces model policy answers `GET /v1/models` with the permitted
  catalogue. Before, it refused the request with `403` because it named no model.
- `client-ip` counts the TCP peer address. `x-forwarded-for` is read only on a non-edge
  connection manager with `xff_num_trusted_hops`, so a client cannot pick its own bucket
  by writing the header.

### Fixed

- The key that `llm-proxy init` and `scripts/install.sh` print now works at once. The
  starter config sets `auth.enforce.tenants_without_policy: allow`, and the proxy warns
  about it at startup. Before, the `default` tenant had no model policy, so the printed
  key got `403 forbidden` until an operator stored one with `PUT /tenants/{id}/policy`.
  An existing config is not changed. The quickstart now shows the OpenAI path from
  `init`.
- The warning logged when a tenant without a model policy is refused no longer contains
  runs of spaces.

### Known limitations

- Limits apply to the fleet only with `auth.store: shared`. With another store each
  replica counts alone, so N replicas can admit up to N times a limit. Between reconciles
  the fleet can admit a little over a limit.
- `client-ip` behind a load balancer is the balancer's address, because the dialect has no
  trusted-hops setting. Trusted hops are available in Envoy mode (`xff_num_trusted_hops`).
- A key budget counts one credential source (the operator key or the tenant's own key),
  not all spend of the key.

## [0.3.6] - 2026-10-14

### Fixed

- Request capture no longer counts two workers admitting at the same moment as
  `capacity_exceeded`. Admission takes a short lock over in-memory accounting, so the
  counter only moves when the capture pool is genuinely full.
- The `listen.stream_idle_timeout` schema description no longer claims it bounds the gap
  between response chunks; every rule's own `idle_timeout` governs that gap.

Also in this tag: real-binary tests pinning cut-stream charging on upstream reset, idle
timeout and `max_stream_duration`, and milestone records for the Dynamic configuration
and Hardening gates, both shipped in tag v0.3.5.

## [0.3.5] - 2026-10-14

### Changed

- **Breaking:** with `llmproxy.model_authz` in the chain (dialect: `auth` with
  `enforce.model_policy` on, the default), a tenant with no stored model policy is
  refused with `403 model_not_permitted` instead of being allowed every model. Grant
  models with `PUT /tenants/{id}/policy` (`{"access":"all"}` grants all), or set
  `auth.enforce.tenants_without_policy: allow` (Envoy mode:
  `ModelAuthz.tenants_without_policy: ALLOW`), which logs a load-time warning.
- `DELETE /tenants/{id}` revokes every key of the tenant, including `auth.keys`
  entries (a revoked store row under the same key id).
- `--mode translate` prints secrets as `[REDACTED]`; `--reveal-secrets` prints them.
- `%REQ(X)%` renders `[REDACTED]` for credential headers (`authorization`,
  `proxy-authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, `cookie`).
- A request whose output-token limit is above `models.<name>.max_output_tokens` (Envoy
  mode: `BodyRewrite.max_output_tokens`, filter level or per route) is refused with `400`
  naming the field and the cap; so is a non-integer or repeated limit. The checked field
  follows the path: `max_output_tokens` for `/responses`, `max_tokens` for `/messages`,
  `max_tokens` and `max_completion_tokens` otherwise. A request with no limit is forwarded
  unchanged. Counted in `llmproxy_router_max_output_tokens_rejected_total`.
- The `spend_limit` warning for an unset node id names `--service-node`.

### Added

- `auth.max_policy_staleness` (Envoy mode `max_policy_staleness_seconds`, default
  4 minutes): past it, with the store unreachable, virtual-key requests get
  `503 auth_policy_stale`. The age is exported as
  `llmproxy_policy_snapshot_age_seconds`.
- The admin API answers `429` with `Retry-After` after 10 bad bearer tokens from one
  peer in 60 seconds, and logs the peer address on every refusal. The admin UI keeps
  its token in `sessionStorage`.
- `envoy_llmproxy_usage_rate_card_active{scope,version}` on `/stats/prometheus` reports
  the rate card each chain prices with (1 for the active version, 0 for a retired one).
  Compare it across replicas to see a card that has not propagated.
- `%LLM_UPSTREAM_ID%` and `%LLM_UPSTREAM_USAGE%` access-log operators, and
  `upstream_response_id` / `upstream_usage` on request and attempt records (schema version
  1, additive): the provider's response id and its `usage` object exactly as sent. Evidence
  only; cost still comes from the rate card. Misses over the size bounds are counted in
  `llmproxy_usage_upstream_usage_oversized_total` and `llmproxy_usage_upstream_id_oversized_total`.
- `HttpFilter::on_stream_complete`: a callbacks-carrying hook that runs once per filter, before
  the access log reads `StreamInfo`, for clean ends, local replies and abandoned streams.
- The config dialect's default access-log formats carry `llm_usage_completeness`,
  `llm_cost_kind` and `llm_upstream_id`; the JSON format also embeds `llm_upstream_usage`.

### Fixed

- A stream the client abandons, or the upstream cuts off, was never metered: no usage, no cost,
  no spend or token-limit charge, and the record claimed `completeness: complete`. It is now
  recorded `partial`, priced through the rate card from an estimate (4 bytes per token: input
  from the request size, output from streamed text; provider figures that arrived are kept),
  and charged by `spend_limit` and `token_limit`. Marked by `usage.provenance: estimate`,
  `cost.kind: estimate`, `%LLM_USAGE_COMPLETENESS%` and `%LLM_COST_KIND%`; counted in
  `llmproxy_usage_partial_total` and `llmproxy_usage_estimated_total`.

Also in this tag: the ADS channel honours the xDS cluster's TLS `transport_socket`; a retry
that runs out of members returns the last upstream response; a route `idle_timeout` of `0s`
disables the timeout; outlier un-eject timers and worker joins move off the runtime. See the
git log for details.

## [0.3.4] - 2026-10-13

Fixes from a production metering review of an OpenRouter deployment run in config mode,
plus auto model resolution and the capture spool view. The "Hardening" milestone gate is
not closed by this tag.

### Changed

- With `auth` configured, the config dialect now runs `llmproxy.model_authz` and
  `llmproxy.spend_limit`, so tenant model policies and budgets written through the admin
  API are enforced. A tenant with no policy or budget stays open.
  `auth.enforce: {model_policy, spend}` turns either off, with a load-time warning.
- `PUT /tenants/{id}/policy` and `PUT /tenants/{id}/budget` answer `409 not_enforced` when
  no listener chain runs the enforcing filter, instead of storing a value nothing reads.
- A request whose body has two `model` keys (including a JSON-escaped one), or whose body
  `model` differs from the routed model, is refused with `400` on every route, not only
  on routes that rewrite the provider model.
- With `force_usage_reporting`, a streaming request always gets usage reporting, including
  when the client sends `include_usage: false`, spells `stream` with a JSON escape, or
  places it beyond the scan window. The Responses and Messages APIs are left alone; they
  report usage unasked.
- Pricing uses the model the provider says it served when the rate card has an entry for
  it; the spend charge uses the same cost. Counted in
  `llmproxy_usage_served_model_repriced_total`.
- Tenant and key ids longer than 128 bytes are refused at mint and at config load.
- `--drain-strategy` warns only when the flag is given.

### Added

- `providers.<name>.request_fields: {deny, strip}` (Envoy mode: `request_field_policy`
  under the cluster's `io.llmproxy.provider_auth` metadata): a generic top-level
  request-body field policy, applied per attempt to the provider actually dialled.
  `deny` answers `400 request_field_not_permitted`. The OpenRouter importer and example
  deny `models`, `route`, `plugins` and `transforms`.
- `auto` model resolution (`llmproxy.model_resolver`, the dialect's `auto` block) and the
  `%LLM_RESOLVED_MODEL%` access-log operator.
- `%LLM_SERVED_MODEL%` access-log operator and `served_model` on attempt records. The
  dialect's default formats carry `llm_served_model` and `llm_credential_source`.
- Metering counters: `envoy_llmproxy_usage_oversized_body_unmetered_total`, record
  admission outcomes `oversize` and `invalid`, `llmproxy_metadata_dropped{reason="drained_after_close"}`
  and `llmproxy_access_log_write_failures`.
- `GET /capture/spool/stats` and `GET /capture/spool/records?after=&limit=` show the
  capture agent's spool. Records are end-user metadata, so they need the admin token
  (`LLMPROXY_ADMIN_TOKEN`), like the spend read. Stats need no token; the proxy caches
  the answer for 5 s and runs one agent query for any number of callers in that window.
  Both answer `404` with no agent configured, `503` when the agent is unreachable,
  `403` when the producer grant lacks `"inspect": true`, and `501` when the agent is too
  old to answer inspection queries.
- The capture agent producer grant has an `inspect` field (default `false`). A grant with
  `"inspect": true` can read stats and the stored records of its own tenants only.
- Prometheus gauges `llmproxy_capture_spool_retained_records`,
  `llmproxy_capture_spool_pending_records`, `llmproxy_capture_spool_disk_bytes`,
  `llmproxy_capture_spool_max_disk_bytes`, `llmproxy_capture_spool_quarantine_bytes`,
  `llmproxy_capture_spool_durable_through_sequence` and `llmproxy_capture_spool_poisoned`,
  polled from the agent every 10 s. `llmproxy_capture_spool_stats_available` is 1 only when
  the last poll returned stats; the spool gauges keep their last values otherwise.
  `llmproxy_capture_agent_reachable` is 0 only when the agent cannot be reached; an agent
  that answers with a refusal still counts as reachable. These have no Envoy equivalent,
  so they appear in `/stats/prometheus` only. The proxy logs once when the agent becomes
  unreachable or recovers, and once when stats are off because the grant lacks
  `"inspect": true` or the agent needs an upgrade.
- The admin UI has a Capture tab with the spool stats and a paged table of stored records.

### Fixed

- `POST /v1/responses` and `POST /v1/messages` on an OpenAI-compatible provider now
  record usage and cost (the usage parser is chosen from the request path).
- OpenAI-format `prompt_tokens_details.cache_write_tokens` is billed at the cache-write
  rate instead of the input rate.
- JSON responses over 1 MiB are metered from a bounded tail of the body; when the usage
  object is not in it, the miss is counted and logged instead of passing silently.
- Oversized and invalid request records are no longer counted as a full queue, and a
  record that failed validation in access logging is no longer dropped uncounted.

Also in this tag: downstream admission limits, DNS cluster re-resolution, pool draining
for removed endpoints, per-host in-flight counts for `LEAST_REQUEST`, stats slot reclamation,
rate-card persistence, and off-thread access-log writes. See the git log for details.

## [0.3.3] - 2026-10-11

Follow-ups to tenant provider credentials: a configurable request body limit, a
save-time key check, and tenant credentials on the Redis `shared` store. The
"Dynamic configuration" milestone gate is still open; this tag does not close it.

### Added

- `listen.max_request_body_bytes` in the `llmproxy` config file sets the largest
  request body the listener accepts (default 1 MiB). It lowers to the listener's
  `per_connection_buffer_limit_bytes`. Write `listen` as an object to use it.
- `PUT /tenants/{id}/provider_credentials/{provider}` checks a tenant key with the
  provider before it stores the key. It sends one `GET` to the cluster's
  `verify_path` and stores the key with `verified_at` set only on a `2xx`. A
  rejected key returns `422 credential_rejected`, and a provider error returns
  `502 credential_verification_unavailable`. Nothing is stored on failure. Send
  `"verify": false` to store the key unchecked. Set the path with
  `providers.<name>.tenant_credential_verify_path` or the Envoy slot's
  `verify_path`. See [Tenant provider credentials](docs/site/src/content/docs/authentication/tenant-provider-credentials.md).

### Changed

- The largest request body that can be retried or fail over is now the listener's
  request body limit, as in Envoy, not a fixed 1 MiB. Before, a listener with a
  raised limit never retried a body over 1 MiB.
- `VERSION` matches the Cargo workspace version, and `make ci` checks it.
- The Redis `shared` store holds tenant provider credentials, so a proxy with
  several replicas can use them. A key stored through one replica reaches the
  others at their next policy poll. Every replica needs the same key-encryption
  key files. Tenant credentials still refuse the `in_memory` store.

### Fixed

- The ext_authz fail-open warning is logged once per process. Before, each worker
  and each config reload logged it again.
- An ext_authz call that runs past its deadline is reported as a timeout, not as a
  transport error, when the authorization service cancels it first.

## [0.3.2] - 2026-10-11

Tenant provider credentials, plus security and drain fixes. The "Dynamic configuration"
milestone gate (ADS ACK/NACK and warming) is still open; this tag does not close it.

### Added

- Tenant provider credentials (bring your own key). A tenant stores its own key
  for a provider with `PUT`, `GET`, and `DELETE`
  `/tenants/{id}/provider_credentials/{provider}`. The key is sealed with
  AES-256-GCM under a 0600 key-encryption key file. A tenant with a stored key runs
  in strict tenant mode: no attempt uses the platform credential. Configure it with
  `providers.<name>.tenant_credentials` and `auth.tenant_credentials` in the
  `llmproxy` config file, or with the `tenant_credential` cluster slot in Envoy
  mode. See [Tenant provider credentials](docs/site/src/content/docs/authentication/tenant-provider-credentials.md).
- `auth.store` in the `llmproxy` config file selects the auth control-plane store:
  `in_memory`, `persistent`, or `shared`.
- Access-log operators `%LLM_TENANT%` and `%LLM_CREDENTIAL_SOURCE%`, the
  `llmproxy_tenant_credential_requests_total` counter, and a `credential_source`
  field on request and attempt records.
- Admin budget routes accept `credential_source` (`platform` or `tenant`).
- `envoy.filters.http.ext_authz` (gRPC service only) in static and xDS config. It
  fails closed by default; `failure_mode_allow` is explicit, warns once, and counts.
- Admin `POST /healthcheck/fail`, `/healthcheck/ok`, and `/drain_listeners`.
- The installer runs under POSIX `sh` (`curl ... | sh`), and by default installs and
  starts the proxy as a launchd agent or systemd unit.

### Changed

- Spend budgets are scoped to one credential source. Existing budgets are
  platform-scoped. A budget counts only the spend in its scope, so tenant-mode
  spend is not counted against a platform-scoped budget.
- Tenant spend budgets are enforced alongside key budgets. When any spend budget is
  configured, a request with no tenant or key identity gets `403 spend_identity_missing`.
- Drain: the first `SIGTERM`/`SIGINT` or `POST /drain_listeners` makes `/ready` answer
  `503 DRAINING`, closes the listening sockets, and closes idle keep-alive connections.
  Upgraded (tunnel) connections keep the drain open until they close or the deadline.
- A listener `per_connection_buffer_limit_bytes: 0` is a load error (a NACK over LDS).

### Security

- Every HTTP request body is capped at the listener's `per_connection_buffer_limit_bytes`
  (default 1 MiB) before any filter runs. A larger body gets `413`. Before, the default
  filter chain buffered an unauthenticated body with no cap.
- `llmproxy.auth` removes the `Authorization` header after it verifies a virtual key.
  Before, providers that take their key in another header (Anthropic) and keyless
  providers (Ollama, vLLM) received the client's virtual key.

### Known limitations

- Tenant credentials apply to virtual-key principals only. A JWT principal always
  uses the platform credential.
- A tenant key is not checked when it is saved. A wrong key shows up as the
  provider's `401`.
- Tenant credentials require the `persistent` store. With `auth.tenant_credentials`
  (or Envoy's `tenant_credentials`), an absent, `in_memory`, or `shared` store is a
  load error at the block's field path. `in_memory` loses stored keys on restart,
  and `shared` loads none, so either would leave tenants on the platform credential.
- The Redis store (`store.shared`) does not hold tenant credentials yet. Writes
  return `500`, and a config cannot select it while tenant credentials are set.
- In tenant mode only `authorization`, `x-api-key`, and `api-key` are cleared. A
  platform key on any other header is still sent with the tenant key.
- In the `llmproxy` config file, a bad key-encryption key file or a duplicate key id
  fails at load, but the error names the Envoy-mode field path.
- If every key-encryption key is lost, stored tenant keys cannot be recovered.
- Rolling back to a build without budget scopes applies tenant-scoped budgets to
  all traffic.

## [0.3.1] - 2026-10-09

Follow-up fixes and optional local metadata capture after v0.3.0.

### Added

- OpenRouter provider defaults, cluster-owned `/v1` to `/api/v1` rewriting,
  and a loopback local example with explicit OpenRouter model entries. The
  configured catalog is served locally at `/v1/models` and refreshed with
  `scripts/import-openrouter-models.py`.
  Chat, SSE, model discovery, and credential replacement are covered by a local
  mock integration test; no live paid requests were made.

- Optional bounded request and attempt metadata capture with authenticated local agent
  delivery, runtime controls, and encrypted redb storage. Durable local receipts follow
  transaction sync; sequence reservations, recovery validation, key rotation, bounded
  cursor replay, and physical disk quotas are covered by fault and process-crash tests.
- Fresh capture spool format with no legacy migration. Removed segment settings fail
  strict configuration validation; `cache_bytes` defaults to 4 MiB, capped at 16 MiB.
  Metadata capture remains LOCAL-SPOOL-ONLY: no backend uploader or query service.
- Linux amd64 and macOS arm64 release archives include the companion capture agent.

### Validation and limits

- Workspace qualification: 2,335 tests passed, 28 skipped; doctests: 5 passed, 1 ignored.
  Formatting, lint, and dependency checks passed locally.
- Production retention: 60,000 records confirmed and byte-verified after reopening,
  within a 1 GiB disk limit, plus escaped and maximum-size record cases.
- Local integrated qualification completed, including CPU/RSS, failure and Disable
  cases, maximum escaped records, and corrected absent-agent reservation draining; see
  the 2026-10-08 redb production qualification (removed; recoverable with `git show 31756dc:<path>`) for evidence
  and explicit limits. This release does not claim 5,000 requests/second,
  100,000 concurrent streams, or completed Envoy parity.

### CI fixes

- Replace the deprecated atomic update in the HTTP/2 refusal test with an atomic
  compare/exchange loop, retaining compatibility with older Rust APIs.
- Pin Rust 1.99.0 for development, CI, and release builds. CI now runs `make ci`
  with nextest, separate doctests, dependency checks, and black-box QA, plus the
  capture reporter checks. This prevents local/CI toolchain drift and uses the
  repository's bounded test configuration.
- Align workspace package and binary versions with the v0.3.1 release tag.
- Put accepted OpenRouter mock sockets into blocking mode before bounded reads,
  fixing a macOS timing failure without relaxing request/response assertions.
- Use a short `/tmp` fixture path for the capture cleanup test on both Linux and
  macOS, fixing the Linux-only missing-directory failure exposed after lint passed.
- Patch the transitive UI build dependency `source-map-js` to 1.2.2, addressing
  GHSA-68fv-2mgg-jv7q; the clean UI build and npm audit pass.

### Operational telemetry

- **Independent OTLP metric export.** Metric export is now configurable and scheduled separately
  from trace export, per `docs/telemetry-design.md` §5.3. Envoy mode reads a new
  `node.metadata["io.llmproxy.metrics"]` namespace (`otlp_endpoint` required; `service_name`,
  `export_interval` (default 15s), `export_deadline` (default 10s) optional) into a new
  `ConfigSnapshot.metrics`; the `llmproxy` dialect exposes the same surface as
  `observability.metrics`, with durations in the dialect's `"30s"` string syntax. Metrics export
  now works with tracing entirely off, and turning tracing on no longer implies metrics on — a
  config that named neither sends nothing, and one that named both sends each signal to its own
  endpoint. `export_interval` is bounded to 1s–1h and `export_deadline` must be shorter than the
  interval, both rejected at load with a full dotted path. The metric exporter runs on its own
  task, ticker, and connection, with a per-export deadline that bounds a collector which accepts a
  connection and then stops responding; forwarding and `/stats` scrape are unaffected by either.
  Two new self-instruments, `llmproxy_otel_export_failures{signal="traces"|"metrics"}` and
  `llmproxy_otel_spans_dropped`, make an unreachable collector visible as a metric rather than as a
  gap in a dashboard; both series exist from the first scrape on a process with no OTLP configured
  at all. This operational telemetry export is separate from the optional metadata capture
  path described below.

- **Review fixes to the above (2026-10-01).** Four findings from review, all fixed: (1) config
  load could PANIC — a huge but finite `export_interval` like `1.0e100` passed the finite/positive
  guards and aborted the process inside `Duration::from_secs_f64`; the conversion is now the
  fallible `try_from_secs_f64` and rejects with a full dotted path. (2) The final metric snapshot
  was requested BEFORE the drain, so it missed drain-period traffic and could delay draining by
  the export deadline; the exporter is now signalled and awaited after `graceful_shutdown`
  returns, and the shutdown budget covers an in-flight snapshot plus the final one. (3) Span
  losses were underreported: failed trace batches counted the failure but not the batch's span
  count, and the drop series was published by the METRIC exporter, so a Prometheus-only deployment
  reported zero forever; the trace exporter now owns a combined queue+batch drop ledger and
  publishes it whatever the metric exporter is doing. (4) Trace export was unbounded — a hung
  collector parked the trace exporter forever; traces now have their own `export_deadline`
  (`TracingConfig::export_deadline`, default 5s, bounded 100ms–60s, dialect
  `observability.tracing.export_deadline`), matching the metric side.

- **Trace shutdown and drop-counter semantics.** Trace producers close after worker drain and
  the proxy waits within a bounded budget for the final trace batch before exporting final
  metrics. Pending exports are cancelled if the shutdown budget expires. Span losses are
  exported as a monotonic counter, including queue losses and failed batches.

## [0.3.0] - 2026-09-29

This release advances **v0.3.0** (ADS/xDS). The proxy now connects to an ADS control plane,
ACKs/NACKs strict LDS/CDS/RDS/SDS/EDS resources, applies accepted snapshots, reconnects with
resync, and gates readiness/request admission on cluster warming. Named RDS delivery warms
dependent listeners; replacement listeners retain last-good generations until warm, and ADS
initial-fetch timeout is honored. Delta ADS now runs end to end for strict incremental resource
updates; filesystem xDS, init-manager sequencing, SDS removal, and full differential churn
verification remain open. Configuration loading rejects unsupported sources with full dotted paths.
Everything else below is WP-50 increment 3 (operator control plane: tenants, budgets, spend),
which shipped between the v0.2.0 tag and this point and gates neither release — see
`internal-docs/MILESTONES.md`'s v0.2.0 section for why it's recorded there.

### Added

- **Delta ADS transport and application.** `DELTA_GRPC` opens `DeltaAggregatedResources` in the
  running binary, carries per-resource reconnect versions and named subscription differences,
  applies before ACK, and incrementally applies CDS/LDS/RDS/EDS updates and removals plus SDS
  updates. Unsupported delta wrapper variants and SDS removals NACK instead of being ignored.
- **xDS warming-race script predicates.** Control-plane scenarios can wait for an exact ACK or
  NACK without unrelated subscriptions advancing the script (`376d8d0`).
- **`x-envoy-upstream-service-time`.** Successful upstream responses report final-attempt elapsed
  milliseconds, replace spoofed upstream values, and omit the header on local failures
  (`498adba`).
- **Vertex bearer-token and Bedrock signing support.** Vertex applies configured access
  tokens and provider paths; Bedrock signs final request bodies with SigV4. Strict validation, IR
  lowering, dialect handling, and focused tests landed in `9c939b9`; Vertex token mint/refresh and
  live-provider E2E remain deferred.
- **Owned Lane-H filter protos.** TokenLimit, Usage, and BodyRewrite now use versioned
  `llmproxy.filters.v0` typed config with legacy borrowed decoders retained for one release.
- **Direct-response file bodies load during config lowering.** Request workers perform no file I/O
  for this path (`24b42fb`).
- **Local rate-limit request header mutations.** `request_headers_to_add_when_not_enforced`
  parses strictly and applies on disabled, no-bucket, not-enforced, and shadow-denied paths
  (`f979f38`).

- **Admin write API, gated by `LLMPROXY_ADMIN_TOKEN`.** `POST /keys` (mints a virtual key,
  returns the plaintext exactly once), `DELETE /keys/{id}`, tenant CRUD, and
  `PUT /tenants/{id}/policy` (per-tenant model allow-lists). Fails closed with `403` when the
  token env var is unset, `401` with a challenge on a wrong token, `503` during the brief
  startup race before a control plane is registered. Request bodies are capped at 64 KiB.
- **Per-tenant spend budgets.** `PUT /tenants/{id}/budget` sets a ceiling (an absent budget is
  unlimited; a configured zero denies everything) with a daily or monthly period. A new
  `llmproxy.spend_limit` filter enforces it against a live in-memory counter, returning `429`
  with `x-ratelimit-*` headers (values in **micro-dollars**, not request counts) on
  exhaustion; the budget restores on period rollover.
- **Per-request pricing.** A `(cluster, model)` price table, in integer micro-dollars, priced
  independently per token bucket (input/output/cached/cache-creation) and resolved against
  the cluster a request actually dialled — never the route — so a failover is billed at the
  fallback's price, not the primary's.
- **`GET /tenants/{id}/spend`**, gated behind the admin token despite being a `GET` (it's
  financial data): live spend, budget and remaining, last-flush time, and the count plus
  distinct `(cluster, model)` pairs of unpriced requests, so an operator can see a pricing gap
  instead of assuming a model is billed when it silently isn't.
- **An end-to-end test drill for the admin write API against the real binary.** Spawns the
  shipped executable with `LLMPROXY_ADMIN_TOKEN` set and a mock upstream, then drives the admin
  surface over a real socket: the `403`/`401`/success gate, a minted key authenticating real
  traffic through the data plane, a revocation taking effect on the very next request, a policy
  write changing enforcement with no reload, a budget write producing `429` with `x-ratelimit-*`,
  and scoped versus unscoped chain addressing. This closes the coverage gap recorded below and
  found the `model_authz` defect above on its first run.
- **A selectable, persistent control-plane store.** The auth filter's config gains
  `oneof store { in_memory | persistent { path } }`; unset defaults to `in_memory`, so every
  config written before this change is unaffected. The persistent option is an embedded
  `redb` database — keys, tenants, policies, and budgets survive a restart.
- **Chains addressed by name, not position.** Admin endpoints are now scoped as
  `/chains/{stat_prefix}/...`, matching the operator-chosen name already required on the HTTP
  connection manager, so reordering filter chains in config can't silently reassign a
  tenant's billing history to the wrong chain. The pre-existing unscoped endpoints keep
  working as a single-chain convenience alias.

### Changed

- **Per-tenant model allow-lists are now enforced live, not just stored.** `llmproxy.model_authz`
  reads the published control-plane snapshot instead of its own static config, so an admin
  `PUT /tenants/{id}/policy` changes what the next request from that tenant is allowed to do,
  with no restart or reload. As part of this, a tenant with no policy in the snapshot is now
  **permitted** every model, reversing the previous default of denying an unrecognized tenant
  — authorization defaults open once a caller is authenticated, consistent with how an
  unconfigured tenant is treated everywhere else in the control plane.

### Fixed

- **`llmproxy.model_authz` refused every request in any filter chain that enabled it.** Per-tenant
  model allow-lists were therefore non-functional: a chain configuring the filter returned `403`
  for 100% of traffic, whatever the policy said. The filter read the requested model during the
  header phase, but that value is published during the body phase, and the proxy runs every
  filter's header callbacks before it delivers any body data — so the value was always absent and
  the filter took its "no model to authorize" denial path. Filter ordering could not affect this
  and no configuration worked around it. The tenant check still happens on headers; the model
  check now happens once the body (or the trailers) has been seen. Requests with no body and
  requests carrying trailers are both still checked, so the fix does not turn a refusal into a
  gap. The filter fails **closed**, so this was an outage rather than an authorization bypass.
- **Security: a configured token-per-minute rate limit admitted roughly (limit × core count)
  tokens per minute, not the configured limit.** The limiter built a separate budget store
  per worker process instead of sharing one; an operator relying on, say, a 1000
  tokens/minute ceiling was silently getting up to 8000/minute on an 8-core box. Fixed by
  sharing one budget per filter chain and rule; existing configs need no changes.
- **Security: two listeners each configuring `llmproxy.auth` could authenticate against the
  wrong one's keys.** The shared factory state that holds parsed auth config (HMAC secret,
  virtual keys, store) was keyed on the filter's type alone, so a second chain's config was
  parsed, validated, and then silently discarded in favor of the first chain's — a request
  presenting the *second* chain's key would authenticate against the *first* chain's tenant
  set. Now keyed per filter chain as well as filter type. Only affects configs with more than
  one `llmproxy.auth`-configured chain.

### Known limitations

- **Spend budgets are enforced per process, not per fleet.** N replicas behind a load
  balancer enforce N independent ceilings — the same shape as the rate-limit bug above, one
  level up, and not yet fixed for spend. Closing it needs an additive/CAS write on a
  distributed `ControlPlaneStore`, which does not exist yet.
- **The admin write API's unscoped endpoints (`/keys`, `/tenants`, ...) support exactly one
  `llmproxy.auth`-configured chain**; with several, they refuse explicitly rather than
  guess. The scoped `/chains/{stat_prefix}/...` form has no such limit.
- OIDC/JWT as a second authentication method is not built; the `Authenticator` trait was
  designed for it but nothing implements it yet.

## [0.2.0] — 2026-08-29

**Production-ready serving.** v0.1.0 made the proxy understand its traffic; this release
makes it safe to run unattended and honest about its own performance.

### The gate

A published capacity report (p99, tokens/sec ceiling, RSS under sustained long-lived
streams) from a run that is not harness-bound, plus `/config_dump` and `/stats` served by
the admin endpoint, plus a config swap under live traffic with zero dropped streams. All
three clauses are met.

- **Admin + stats** — `/config_dump`, `/stats` (Envoy text), and `/stats/prometheus` are
  served and report real traffic, proven by `crates/proxy/tests/stats_e2e.rs` against the
  real binary and a real HTTP scrape.
- **Capacity report** — published from a not-harness-bound run (`054b809`), unblocked by
  HTTP/1.1 and HTTP/2 upstream connection reuse.
- **Config swap under load** — SIGHUP re-reads the config file and publishes a new
  snapshot; a parse failure keeps the previous snapshot serving and logs the full
  dotted-path detail. Proven by `testing/diffrig/tests/swap_under_load.rs`: streams in
  flight at the swap, all SSE streams reaching their terminal frame, zero transport errors.

### Added

- **Metrics registry (WP-23)** — an OpenTelemetry-native internal model (instruments plus
  attribute sets) rendered to Envoy-exact `/stats` text and to Prometheus, with histograms
  on Envoy's default buckets.
- **Admin server (WP-25)** — `/config_dump`, `/clusters`, `/stats`, `/stats/prometheus`,
  each resolving the live snapshot after a reload rather than the boot snapshot.
- **Active health checking (WP-18)** and **outlier detection (WP-19)** — reachable from
  config and running; an active-health-check recovery clears an outlier ejection.
- **Circuit breakers and connection reuse (WP-15)** — `max_connections` enforced at the
  dial site; per-worker HTTP/2 multiplexing and HTTP/1.1 keep-alive upstream connection
  pools.
- **OpenTelemetry (WP-51)** — distributed spans (W3C trace-context join/propagation) plus
  OTLP/gRPC export of both traces and metrics, zero-cost when unconfigured.
- **HTTP upgrades and WebSocket tunneling (WP-10, S10)** — transparent HTTP/1.1 Upgrade
  and HTTP/2 extended CONNECT (RFC 8441) tunnels, gated by `upgrade_configs`, with an idle
  timeout on the tunnel.
- **Routing (WP-13)** — `x-envoy-attempt-count`, redirect route actions.

### Changed

- `loadgen` percentiles now describe successful requests only, and the driver detects SSE
  truncation (a cut-short stream is no longer counted as success) — both were measurement
  defects that would have skewed a published capacity number.

## [0.1.0] — 2026-08-08

**The pipe gets smart.** v0.0.1 proved a request could go all the way through. This release
is about the proxy _understanding_ what is going through it.

### The gate

The proxy emits per-request token counts (input / cache-read / cache-write / output) and
TTFT/TPOT to the access log, enforces a token-based rate limit, and fails over from one
provider to another mid-request without the client seeing an error.

All three clauses are verified end to end against the real binary over real sockets, not
merely implemented — **against mock upstreams**. Unlike v0.0.1, this release was tagged
without executing its live-provider drill; that drill exists
(`testing/diffrig/tests/live_gate_v0_1_0.rs`, one command, three billable calls) and the
departure from v0.0.1's standard is recorded in `internal-docs/MILESTONES.md`.

- **Token counts + TTFT/TPOT** — QA-10 (`testing/qa/scenarios/qa10_llm_latency_test.go`)
  against a mock paced at 400ms TTFT / 150ms inter-chunk: `ttft=402ms tpot=122.129ms
max_stall=152ms`. QA-1 covers per-route counts for both providers from one config.
- **Provider failover** — `testing/diffrig/tests/failover_e2e.rs`: primary forced to 429,
  fallback serves, attempt accounting exact, and the standby receives its own credential
  with the primary's appearing nowhere.
- **Token rate limiting** — `testing/diffrig/tests/auth_e2e.rs`: a tenant's budget is
  exhausted and a _second, different_ key belonging to that tenant is refused with 429.

**Read this clause carefully, because the obvious version of it is not what shipped.** A
token limit was already enforced in code before this release, and that was not enough. The
limiter bucketed on the client's own `Authorization` header, and nothing verified that
header — so any caller who exhausted a quota changed one string and received a fresh one.
The limit was advisory by construction. Closing this clause required giving callers an
identity the _proxy_ assigns, which is why downstream authentication is in this release at
all. It was not planned scope; it was the precondition.

### Added

- **Downstream authentication (WP-50 increment 2a).** Proxy-issued virtual keys, verified as
  keyed HMAC-SHA-256 digests in constant time, resolving a request to a tenant. Fails
  **closed**: with the filter configured, an unrecognized credential is a 401, always.
  Configuration carries only digests — a plaintext key never appears in a config file.
  Authentication is an `Authenticator` trait behind a chain, so OIDC lands later as a second
  implementation without reshaping anything above it.
- **Token budgets keyed on tenant.** The rate limiter now buckets on the authenticated
  tenant when there is one, and on the hashed credential only when no auth filter ran. The
  two key spaces are distinguished by descriptor _name_, so they cannot collide.
- **`auth:` in the `llmproxy` dialect**, plus `limits: key: tenant`.
- **Provider fallback (WP-35).** `fallbacks:` in the dialect lowers to an Envoy aggregate
  cluster with member-order failover, and per-provider credentials travel on the _cluster_
  so a failover cannot send provider A's key to provider B's endpoint. Same-dialect chains
  only; a cross-dialect chain is a config-time error, not a silent drop.
- **Body-based model routing and forced usage reporting (WP-45).** A bounded request-body
  prefix scan routes on the `model` field in the body, and splices
  `stream_options.include_usage` into OpenAI-dialect streaming requests — without which an
  OpenAI-compatible provider reports no usage in a stream at all.
- **TTFT/TPOT (WP-46).** `%LLM_TTFT%`, `%LLM_TPOT%`, `%LLM_MAX_STALL%`,
  `%LLM_RESPONSE_CHUNKS%`, carried by both dialect log formats.
- **The first Lane-H proto (WP-47 increment 1).** `llmproxy/filters/v0/auth.proto` — the
  first config message this project defines rather than borrowing an unrelated Envoy one.
- **Lane-H filter ordering is validated at config load.** Two orderings among the LLM
  filters fail silently when reversed; both are now errors naming the filter to move and the
  consequence.

### Fixed

- **Usage reported as a JSON float billed as zero.** `as_u64()` returns `None` for any
  number that is not a non-negative integer — including an ordinary `150.0`, which real
  providers emit — so `unwrap_or(0)` recorded a genuine usage report as zero tokens,
  silently, with the request succeeding. All five call sites now route through one helper
  where unparseable input is `None` (renders absent), never `0` (a number someone bills
  against).
- **`%LLM_RESPONSE_CHUNKS%` over-reported by one** on every response with a body, and fed a
  phantom gap into `%LLM_MAX_STALL%`: the synthetic empty end-of-stream frame was timed as a
  chunk.
- **The dialect silently dropped `fallbacks:`.** It parsed, validated, lowered, and was
  discarded with one stderr warning — an operator who configured failover got a proxy that
  did not fail over.

### Known limitations

- **Authentication keys live in config and are in-memory only.** No persistent or shared
  store yet, so revoking a key means a config change (WP-50 increment 2b). Multi-instance
  deployments have no shared key set.
- **Authorization defaults open.** An authenticated tenant with no configured policy may use
  every model and provider; per-tenant allow-lists and budgets are WP-50 increment 3.
- **No admin API.** Keys are minted with the CLI and pasted into config; there is no
  create/revoke endpoint and no spend history.
- Upstream connections are still **not pooled** (WP-15).
- Downstream HTTP/2 and protocol upgrades (S10) are not implemented.
- xDS and the stats registry are not wired (v0.2.0/v0.3.0).
- Cross-dialect fallback (OpenAI primary → Anthropic fallback) is rejected at config time;
  it needs request/response translation (WP-52, v1.0.0).
- Every gate verification runs against mock upstreams. v0.0.1's gate was closed by a manual
  live run against real OpenAI and Anthropic endpoints; the equivalent for this release's
  two new clauses is recorded in `internal-docs/MILESTONES.md` as a judgment call rather than a
  completed step.

## [0.0.1] — 2026-08-01

**First light.** One request, all the way through, for real.

### The gate

A client sends a chat-completion request to the proxy, configured from a single `llmproxy`
config file pointed at a real provider endpoint, and receives the provider's response back
unmodified — both non-streaming and streamed (SSE) — for OpenAI and for Anthropic.

Closed by `testing/diffrig/tests/live_smoke.rs`: four cases against the real OpenAI and
Anthropic endpoints, all passing. Those tests are `#[ignore]`d by design — they bill real
tokens and CI holds no keys — so this gate's evidence is a deliberate manual run:

```sh
OPENAI_API_KEY=... ANTHROPIC_API_KEY=... \
  cargo test -p diffrig --test live_smoke -- --ignored
```

The release carries everything built to date. The features were never the milestone; the
working path through them was.

### Added

- **Config.** Envoy bootstrap (YAML/JSON) → typed protos → PGV-subset validation → internal
  IR, in strict mode: every field either maps or errors with its full dotted path. Plus the
  `llmproxy` dialect (`--config`), which lowers providers → clusters + upstream TLS + auth
  headers, with `--mode translate` to print the equivalent Envoy bootstrap.
- **L4.** Listener manager with the 9-step filter-chain matcher, `SO_REUSEPORT` bind/accept,
  and `tcp_proxy` serving real bidirectional streams with half-close and idle timeout.
- **TLS.** Downstream and upstream, SNI, ALPN, SAN matchers, mTLS, dual-cert hot reload. An
  upstream `transport_socket` with no registered builder is a fatal startup error, never a
  silent plaintext downgrade.
- **HTTP.** h1 downstream; h1 and h2 upstream, dispatched by config. Filter manager
  implementing S2 (ordering, buffering, local replies, injection, streaming encode). Route
  table implementing S1 (domain precedence, first-match-wins, weighted pick).
- **Router.** S9 request transforms (XFF, `x-request-id`, `:authority`, rewrites,
  `request_headers_to_add`) and S4 timeouts (route, idle, per-try) that disarm on response
  headers so streams are not truncated. S3 retry engine with fully-jittered backoff and body
  replay. S5 `max_requests` circuit breaker.
- **Clusters.** Cluster manager over `ArcSwap`; STATIC/STRICT_DNS/LOGICAL_DNS discovery; S7
  load balancers (round-robin SWRR, random, least-request P2C); active health checking; S6
  outlier detection.
- **Observability.** Access logs with the command-operator format engine and file/stdout/stderr
  sinks with logrotate reopen, emitted at stream end so streamed responses log real
  `bytes_sent`.
- **LLM.** Token extraction for OpenAI chat completions, OpenAI Responses, and Anthropic
  Messages — streaming and not — into four non-overlapping cost buckets, wired into the
  encode path per-route via the dialect.
- **Test infrastructure.** Differential rig against real Envoy v1.38.0 (docker-gated);
  hermetic TLS end-to-end with a generated CA; a third-party tier against a local Ollama;
  config corpus scorecard; in-process xDS control-plane puppet; open-loop load generator
  with a capacity model; and a black-box Go QA suite.

### Fixed

- **Credentials never reached providers.** `request_headers_to_add` was lowered onto
  `RouteEntry` by both config front-ends and read by nothing, so every request arrived at
  its provider unauthenticated. It survived a full plan audit because the config parsed,
  validated, and translated correctly — and then evaporated. Found only because an
  end-to-end test's mock _required_ the header and returned 401.
- **Two upstream certificate-verification holes in the `llmproxy` dialect.** A provider with
  no `ca_file` emitted no validation context at all, which on the rustls side means _accept
  any server certificate_; and the `ca_file` path verified chain trust without verifying
  identity. Both branches now emit a validation context and a DNS-exact SAN matcher on the
  provider host. Envoy-mode parity is deliberately unchanged — Envoy really does default to
  accept-any, so the fix belongs in our own surface, not in the compatibility layer.
- **Credential leak into access logs.** Credentials are now snapshotted out before
  route-injected auth headers are applied.
- Two `StreamInfo` layering bugs that only a socket-level test could find: Envoy owns
  `StreamInfo` at the filter-manager level and logs above the chain.

### Known limitations

- Upstream connections are **not pooled** — still connect-per-stream (WP-15). Four smoke
  requests cannot surface this; a sustained workload will.
- Downstream HTTP/2 and protocol upgrades (S10) are not implemented.
- xDS, the admin server, and the stats registry are not wired (planned for v0.2.0/v0.3.0).
- Token rate limits, model routing, provider fallback, and GenAI TTFT/TPOT metrics are
  v0.1.0 scope. v0.0.1 proves the pipe works; making the pipe smart is next.
- The dialect matches models on the `x-llmproxy-model` header, not on the request body.
