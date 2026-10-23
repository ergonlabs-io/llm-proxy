---
title: Spend policies
description: "Set dollar ceilings on keys and tenants, learn which endpoints a budget can count, and see how spend is shared across replicas and recovered."
summary: >-
  How key and tenant spend budgets work, the admin calls that set them, which
  endpoints a budget refuses, how estimated charges for cut streams work, and
  how replicas share spend through the auth store.
lastUpdated: 2026-10-21
related:
  - limits-and-budgets/pricing-and-cost-tracking
  - limits-and-budgets/token-rate-limiting
  - limits-and-budgets/billing-ledger
  - authentication/virtual-keys
  - authentication/tenant-provider-credentials
  - administration/admin-api
---

Use a spend budget to stop a key or a tenant from spending more than a set
amount in a period. To enable it, add an `auth:` block and a `pricing` rate
card to the config file. Then set a ceiling with `PUT /keys/{id}/budget` or
`PUT /tenants/{id}/budget` on the admin API. See
[Set a budget](#set-a-budget).

Spend enforcement uses two kinds of ceiling, and either one can refuse a
request. A key budget counts the spend of one stable `key_id`. A tenant budget
counts the spend of every key of one tenant. Each ceiling uses its own UTC
budget period (`daily` or `monthly`) and counts spend across every model and
selected provider. A key budget never grants model access.

A JWT caller counts against the budget of its tenant. For a ceiling on one JWT
user, mint a key whose `key_id` is the JWT user id under the same tenant, and
set a key budget on it. The schema describes the user id for `auth.jwt[].user`.
No end-to-end test covers a budget on a JWT user.

## At a glance

- **Default when unset:** a missing budget means unlimited. An explicit zero
  denies the first request.
- **Needs:** an `auth:` block and a `pricing` rate card. With `auth:` and no
  `pricing`, every request costs $0, a budget never fires, and the proxy warns
  at load.
- **Failure mode, unpriced request:** fails open and loud. The proxy serves a
  request that the rate card does not price, adds $0 to every budget, and logs
  a warning.
- **Failure mode, uncountable endpoint:** fails closed. A budget refuses an
  endpoint that it cannot count with `403`.
- **Failure mode, store:** fails open and loud. If the shared store is
  unreachable, a replica admits against the last confirmed total plus its own
  spend.
- **Overspend:** the proxy checks spend at admission and records it at the end
  of the response. Concurrent requests can finish above a ceiling. See
  [Admission and overspend](#admission-and-overspend).

## Example

This file enforces budgets for one provider. The rate in the card is an example.

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  store:
    persistent:
      path: ./llmproxy-auth.redb
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
pricing:
  price_list:
    version: example-2026-10
    effective_from: "2026-10-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: example-chat-model
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 150
            cached_input_nanodollars_per_token: 75
            cache_write_nanodollars_per_token: 200
            output_nanodollars_per_token: 600
```

Start the proxy with `LLMPROXY_ADMIN_TOKEN` set. Then follow
[Set a budget](#set-a-budget).

## How the proxy charges

Charges use integer micro-dollars and the rate card for the provider that the
proxy dialled, also after a fallback. The proxy rounds each charge up to a
whole micro-dollar. See
[Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/).

Set `auth.enforce.spend: false` to leave spend enforcement out. The proxy then
warns at load. `PUT /tenants/{id}/budget` returns `409` with
`{"error":"not_enforced", ...}` instead of storing a budget that nothing
enforces.

A request that the rate card does not price adds $0 to every budget. The spend
reports count these requests in `unpriced_requests`.

When a budget applies to such a request, the proxy logs one warning for each
model. The warning names the model, the provider, and the reason. It also
tells you to add the model to the rate card. A request with no applicable
budget logs nothing. The proxy remembers at most 256 model names. After that it
logs one summary line and names no more models. The request still adds $0 and
still counts in `unpriced_requests`.

The proxy does not reject a request because its model has no price. It serves
the request, adds $0 to the budget, and logs the warning above. This is a
choice for availability. The proxy learns the provider that serves a request
only when the router dials it, after the spend check has admitted the request.
A model that the rate card prices on one provider can be unpriced on its
fallback provider. Rejecting at admission would therefore refuse requests that
are priced correctly. To close the gap, give every model on every provider of a
route a price. Then watch the warning and the `unpriced_requests` count in the
spend reports, and treat a non-zero value as unbilled traffic.

## Endpoints a budget cannot count

The proxy can count the cost of eleven kinds of request: chat completions,
completions, Responses, Messages, embeddings, image generation, image edits,
speech, transcription, translation and `realtime` sessions. It cannot count the
cost of other endpoints, such as batches and files. A budget that applies to a request for
one of these endpoints refuses it with `403` and the response-code detail
`endpoint_not_metered`. The request does not reach the provider.

A budget also refuses, in the same way, a speech, transcription, translation
or image edit request whose cost the proxy cannot count from its shape. It
decides this when it has read the request body:

| Endpoint | Refused under a budget when |
|---|---|
| Image edits | the form has no `model` field |
| Speech | the body has no `model`, or no string `input` |
| Transcription | the form has no `model`, or `response_format` is `text`, `srt` or `vtt` (those responses carry no usage) |
| Translation | the form has no `model`, or `response_format` is not `verbose_json` |

A field that the client sends twice, sends as a file, or sends with a
`Content-Transfer-Encoding` does not count as sent: the provider could read it
differently.

- The proxy finds the endpoint from the request method and path, before any
  path rewrite. It compares whole path segments, so
  `POST /v1/messages/batches` is not a Messages request.
- Every path that the proxy does not know is refused in the same way. An
  endpoint that a provider adds later is refused under a budget until the
  proxy can count it.
- Three endpoints cost nothing and always pass: `GET .../models`,
  `GET .../usage` and `POST .../messages/count_tokens`. Their responses carry
  no usage, and the proxy does not log a missing-usage warning for them.
  Nor does it log one for a request that reached no provider, such as the
  synthetic `404` for an unknown model: nothing was spent.
- There is no exception for a request that matches no route. The proxy reads
  the model from the body after it chooses a first route, so a request can
  match no route at first and reach a provider later.
- A request that no budget applies to is not refused and logs nothing.
- A tenant budget applies only when its credential scope matches the request
  (`credential_source`). A key budget applies to requests on the platform
  credential, and to requests on the tenant's own key only with
  `include_byok_in_limit: true`. A refused request adds nothing to any budget.

Each refusal increments
`llmproxy_unmetered_endpoint_refused_total{endpoint, control}`. `control` is
`spend` for a budget and `token_limit` for a token limit (see
[Configure rate limits](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/#endpoints-a-token-limit-cannot-count)).
`endpoint` is one of `image_generation`, `image_edit`, `speech`,
`transcription`, `translation` and `unmetered` (every other path). The access
log shows the detail in the field `response_code_details`.

## Realtime sessions

A `realtime` session is one long WebSocket. The proxy adds up the `usage` of
each `response.done` event of the session and charges the total for the
session. It does not keep the audio. A `response.done` event without
readable usage, and a response still open when the session ends, are not
charged. The proxy counts each one in
`llmproxy_realtime_usage_missing_total{reason}` and logs a warning. See
[Realtime](/docs/llm-proxy/api-compatibility/realtime/).

## Image generation and edits

A rate-card entry has a `basis`. The default, `tokens`, prices the token
buckets as before. `images` prices the number of images that the response
returned, with `image_prices` rows (the rates here are examples, not a
provider's prices):

```yaml
- provider_type: openai
  model: example-image-model
  basis: images
  image_prices:
    - { nanodollars_per_image: 70000000 }
    - { size: "1024x1024", quality: high, nanodollars_per_image: 90000000 }
```

- The proxy counts the elements of the top-level `data` array of a JSON
  response, or the `*.completed` events of a stream. It reads the response
  as it passes and does not keep the images.
- `size` and `quality` come from the response, or from the request body when
  the response does not show them. The most specific row that matches wins:
  both attributes, then one, then none. Two rows that can match the same
  request at the same specificity are a load error.
- If no row matches, or the response returned no images, the request is
  unpriced: it is charged $0 and the proxy logs a warning once per model.
- Models that bill images in tokens, such as `gpt-image-1`, use
  `basis: tokens`. Each tier can set `image_input_nanodollars_per_token`,
  `image_output_nanodollars_per_token`, `audio_input_nanodollars_per_token`
  and `audio_output_nanodollars_per_token`. Set each one on every tier of the
  entry or on none. When one is set, those tokens are charged at it. When it
  is not set, they are charged at the text rate, as before, and the request is
  counted in `llmproxy_usage_underpriced_modality_requests_total`. Under a
  budget the proxy also logs a warning once per model.
- A cut image response is charged for the images that were complete and the
  tokens that were reported. The proxy does not estimate it from its size.
- Image edits (`POST .../images/edits`) are priced the same way. The request
  is a `multipart/form-data` upload; the proxy reads its `model`, `size` and
  `quality` fields and does not keep the image.
- A token limit still refuses image generation and edits: the proxy cannot
  count their tokens for every model.

## Speech and transcription

Two more bases price audio (the rates here are examples, not a provider's
prices):

```yaml
- provider_type: openai
  model: example-speech-model
  basis: characters
  nanodollars_per_character: 15000      # 15 USD per million characters
- provider_type: openai
  model: example-transcription-model
  basis: audio_seconds
  nanodollars_per_second: 100000        # 0.006 USD per minute
```

- `characters` prices the characters of the speech request's `input`. A
  character is one Unicode code point after JSON unescaping. The charge is the
  characters times the rate, rounded up to a whole micro-USD. It is charged
  only when the response status is 2xx, once, at the entry of the provider
  that served the request. A speech response that is cut is still charged for
  its characters.
- `audio_seconds` prices the audio duration that a transcription or
  translation response reports: `usage.seconds` of a `duration` usage, else
  `usage.prompt_audio_seconds`, else the top-level `duration` of a
  `verbose_json` response. The proxy prices it per millisecond and rounds up to
  a whole nanodollar. It does not apply a minimum duration.
- Models that report tokens, such as `gpt-4o-mini-tts` with
  `stream_format: sse` or `gpt-4o-transcribe`, use `basis: tokens`, with the
  audio token rates above. A response that reports no unit of its entry's
  basis is unpriced: it is charged $0 and the proxy logs a warning once per
  model.
- Transcription and translation requests are `multipart/form-data` uploads.
  The proxy routes them on their `model` field, as it does a JSON body, and
  writes a provider's model mapping into that field.
- A token limit still refuses speech, transcription and translation.

`examples/llmproxy-media.yaml` is a complete card for these endpoints. It
states which provider facts are assumptions until they are checked against a
recorded response.

A card that uses `basis`, `image_prices`, `nanodollars_per_character`,
`nanodollars_per_second` or a modality rate is stored at rate
card schema version 2. An older replica ignores a version 2 card and keeps its
last card. Upgrade every replica before you publish such a card with
`PUT /pricing`. A card that uses none of these fields keeps its version and its
charges.

## Cut streams and estimated charges

A response stream that ends early is still charged, once. The client can
disconnect, the provider can reset the connection, or an idle or duration
timeout can cut the stream. The proxy records the request as `partial` and
charges the spend budget and the token window from an estimate:

- Counts that the provider reported before the cut are used as sent.
- A missing input count is estimated from the size of the forwarded request
  body, at 4 bytes per token.
- The output count is the larger of the provider's figure and the text that
  the proxy forwarded, at 4 bytes per token.

The access log shows `llm_usage_completeness="partial"` and
`llm_cost_kind="estimate"`. The counter `llmproxy_usage_partial_total` counts
these requests.

The estimate is not the provider's bill. The provider can generate tokens
after the cut that the proxy never sees, so the charge can be too low. Real
tokens are not exactly 4 bytes each, so the estimate can also be high or low
for the text that the proxy did see.

A client that disconnects before the provider sends response headers is not
charged and gets no access log line. The provider can still bill the input
tokens of that request.

## Set a budget

Set a budget through the bearer-gated admin API. This call sets a monthly
ceiling of 100 USD on a key:

```bash
curl --max-time 10 -X PUT http://127.0.0.1:53422/keys/alice-laptop/budget \
  -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"schema_version":2,"budget":{"max_usd":"100.00","period":"monthly"}}'
```

The call returns `204`. Add `"include_byok_in_limit":true` to a key budget
to also count spend on the tenant's own provider key. The default is `false`.
`PUT /tenants/{id}/budget` takes the same body for a tenant, except that it
takes `credential_source` instead of `include_byok_in_limit`. See
[Budgets](/docs/llm-proxy/authentication/tenant-provider-credentials/#budgets).

- `period` is `daily` or `monthly`. Both use UTC.
- `{"budget":null}` clears the ceiling.
- `GET /keys/{id}/spend` returns the ledger of a key. `GET /tenants/{id}/spend`
  returns the ledger of a tenant. `GET /keys` lists the policies without
  exposing secrets. These reads need the admin token.
- A tenant with no model policy gets `403` for every model until you grant
  models with `PUT /tenants/{id}/policy`. See
  [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).
- Key API responses show `schema_version: 2`. A key mint or budget request can
  leave out the version or send `2`. The proxy rejects other versions.

`POST /keys` with the same `key_id` and tenant rotates an active key. The new
secret immediately replaces the old one on the receiving replica. There is
**no secret overlap**. Other replicas observe it through the identity-policy
poll, within its bound when the store is reachable. Budget, spend, and model
grants remain unchanged. In-flight requests that are already authenticated keep
their identity and finish normally.

Ownership of a logical key ID is immutable. Minting that ID for another tenant
returns `409`. `DELETE /keys/{id}` revokes its secret and retains a permanent
tombstone. Reminting the revoked ID returns `409`, even after tenant deletion.
Create a new logical ID for a new key. Retained rows prevent accidental ledger
reset or reassignment.

## Tenant budgets

`PUT /tenants/{id}/budget` sets or clears a tenant budget with the same body as
a key budget, except that it takes `credential_source` instead of
`include_byok_in_limit`. `GET /tenants/{id}/spend` returns the tenant ledger. The ledger
adds the spend of every key of the tenant, in the tenant budget's own period.

A request gets `429` when its key ceiling or its tenant ceiling is reached.
Clearing one ceiling does not change the spend or the ceiling of the other. A
tenant budget counts only the requests in its credential scope, and a key
budget counts BYOK requests only with `include_byok_in_limit`; see
[Budgets](/docs/llm-proxy/authentication/tenant-provider-credentials/#budgets).
`%RESPONSE_CODE_DETAILS%` shows `spend_budget_exceeded` for the `429`.

When any key budget or tenant budget is configured, a request without an
authenticated key identity returns `403`. A request that has a key but no
tenant also returns `403` when any tenant budget is configured.
`%RESPONSE_CODE_DETAILS%` shows `spend_identity_missing` for both.


## Shared accounting and crash recovery

The proxy keeps spend totals in the store that `auth.store` selects. Each
replica counts spend in memory and flushes pending charges to the store every 5
seconds. Request workers never query the store. The store decides what a
restart keeps:

| `auth.store` | Effect on spend |
|---|---|
| `in_memory` | Totals live only for the life of the process. A restart resets spend. |
| `persistent` | Totals survive a restart. Other replicas do not read the file. |
| `shared` | Redis holds the totals. Every replica adds to them and reads them. |

With `auth.store: shared`, each live replica needs a distinct, stable
`--service-node`. Use the same ID after a restart. Redis spend keys expire 32
days after their period ends.

The flusher sends pending charges as numbered attempts. Redis drops a repeated
attempt, so a retry after an unclear reply does not count a charge twice.

A `SIGKILL` loses the charges that the replica did not flush yet, up to about
one flush interval of spend. During a store outage it also loses every charge
the store did not confirm, which is the whole outage backlog. To keep that
backlog, set `auth.spend.recovery_journal_path`:

```yaml
auth:
  store: { shared: { url: "${LLMPROXY_REDIS_URL}" } }
  spend:
    recovery_journal_path: /var/lib/llm-proxy/spend-journal.redb
```

On each flush the replica writes its unconfirmed charges to this local file
before it writes to the store. At the next start it replays the file into the
store before it serves, or on a later flush if the store is still down. A `SIGKILL` then loses only the charges since the last
flush. Give each replica its own file on storage that survives a restart of
the process. The journal needs `--service-node`, because it records the node
ID and refuses to replay under another one, and a `persistent` or `shared`
store.

Startup prefetch and the flusher load shared totals. If the startup prefetch
cannot read Redis, the listener still starts and logs one warning. Until the
first successful flush, the rows it could not read count only this replica's
spend, so a budget can be over-admitted for that time.

During a Redis outage, admission continues against the last confirmed global
total plus local accrual. A replica still denies once its own view reaches the
ceiling. After 60 seconds without a successful flush of every row, the flusher
warns, and the replica counts each admission in `unreconciled_admissions`.
Authentication boot remains
fail-closed when Redis is unavailable. A running replica keeps its last
published identity-policy snapshot. Recovery composes the retained deltas and
refreshes the totals of all replicas.

Admin spend reports expose `last_flush_at`, `reconciliation_age_seconds`,
`reconciliation_expired`, and `unreconciled_admissions`. Monitor the
reconciliation age.

## Past-period buckets

The proxy keeps one spend bucket for each key or tenant and each budget
period. A bucket whose period has ended is settled after one successful
reconciliation with the store since the period ended, if it has no pending
charge. A settled bucket costs the store nothing more: the flusher does not
visit it, and the recovery journal does not grow with it. The proxy keeps a
settled bucket readable in memory until 1 hour after its period ends. Then
it evicts the bucket.

A charge that arrives after eviction creates the bucket again. The new bucket
starts from the last flush sequence of the store, so the store total stays
exact.
A report for an ended period with no bucket in memory reads the store and
creates nothing. The unpriced-request detail of an evicted bucket does not
survive eviction.

## Admission and overspend

Spend is checked at admission and recorded at response completion. There are
**no spend reservations**. Every concurrent request admitted while the visible
total is below the ceiling can finish above it. Remote spend is also invisible
until reconciliation. Overspend includes the sum of those admitted in-flight
costs and unreconciled remote charges. Without separate concurrency and
per-request cost limits, there is no finite strict overspend bound. Sequential
single-replica traffic can overspend by one request's cost.

The default access-log formats carry the fields `tenant`, `key_id`,
`user_id`, `requested_model`, `selected_model`, `rate_card_version`,
`selected_provider`, the token counts, `llm_list_cost_nanodollars`, the status,
and the latency. A missing user identity is `-`. Key and user IDs are never
metric labels.

## Limitations

- There are no spend reservations. Overspend is possible. See
  [Admission and overspend](#admission-and-overspend).
- A budget cannot count batches, files, and unknown endpoints. It refuses them.
- A tenant budget counts only the requests in its credential scope. A key
  budget counts requests on the tenant's own provider key only with
  `include_byok_in_limit: true`.
- A request with no price adds $0. Give every model a price.
- A `SIGKILL` loses the charges since the last flush. Without
  `auth.spend.recovery_journal_path` it also loses the backlog of a store
  outage.
- A budget has a period of `daily` or `monthly`. There is no other period.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

This section is for maintainers.

- Spend filter: `crates/proxy-filters/src/spend_limit_filter.rs`. Tests in the
  same file: `an_unpriced_model_without_a_budget_stays_silent`,
  `the_remembered_model_names_are_bounded_and_the_cap_logs_one_summary`,
  `tenant_budget_aggregates_keys_with_independent_periods`
  (tenant ledger and separate ceilings),
  `tenant_zero_budget_applies_without_any_key_budget`, and
  `missing_identity_cannot_bypass_a_tenant_budget` (the `403`).
- End-to-end tests: `tenant_budget_aggregates_multiple_keys_and_enforces_both_scopes`
  in `testing/diffrig/tests/admin_e2e.rs` (two keys, one tenant ceiling, real
  binary); `crates/proxy/tests/unmetered_endpoint_e2e.rs` (unmetered endpoint
  refusal).
- Settled-bucket grace: `SETTLED_BUCKET_GRACE_SECS` in
  `crates/proxy-control/src/spend.rs`. Test:
  `a_late_charge_after_eviction_reseeds_from_the_store_and_lands_exactly_once`.
