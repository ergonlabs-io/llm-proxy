---
title: Chargeback tags
description: "Attribute spend to a project, team or cost centre with operator allow-listed tags on usage records and ledger entries."
summary: Tags from key metadata, JWT claims and an optional request header, filtered by an
  operator allow-list, carried into the request record and the billing-ledger
  entry. How to configure them, set them on a key, and read them back.
lastUpdated: 2026-10-21
related:
  - limits-and-budgets/billing-ledger
  - authentication/virtual-keys
  - administration/admin-api
  - observability/metrics-and-stats
  - configuration/reference
---

Use chargeback tags to attribute spend to a project, a team or a cost centre.
A tag is a `key=value` pair. The proxy writes the accepted tags of a request
into its request record (`tags`) and into its billing-ledger entry
(`record.tags`). A finance system can then group the charges by tag.

Tags are attribution only. There is no tag budget. Budgets stay on the tenant
and the key. See [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

## At a glance

- **Default when unset:** no tags. Without `auth.chargeback_tags`, the proxy
  attributes no tags, does not copy key metadata, and does not read the header.
- **Failure mode:** a tag that fails a rule is dropped and counted. The proxy
  serves the request. A bad tag never refuses a request.

## Where tags come from

- **Key metadata.** The admin sets tags on a virtual key with the admin API,
  or with `auth.keys[].tags` in the config file. Each request that the key
  authenticates gets these tags.
- **JWT claims.** For a JWT caller, the operator maps verified claims to tags
  with `auth.jwt[].claim_tags`. The identity provider sets these tags. See
  [Tags from JWT claims](#tags-from-jwt-claims).
- **The `x-cost-tags` request header.** The client sends comma-separated
  pairs, for example `x-cost-tags: project=search,team=infra`. The proxy reads
  this header only if `from_header` is `true`.

If key metadata and the header set the same tag key, the key metadata wins. A
client cannot change a tag that the admin set. Claim tags work the same way: a
client cannot change a tag that a claim mapping sets.

A request gets tags only from its own key and its own header. A tenant cannot
put tags on the requests of a different tenant.

## Configure the allow-list

Add `chargeback_tags` to the `auth` block. Without it, the proxy attributes no
tags, does not copy key metadata, and does not read the header.

```yaml
auth:
  hmac_secret_file: /run/secrets/llmproxy-hmac
  chargeback_tags:
    from_header: true
    max_tags: 8
    max_value_bytes: 64
    allowed:
      - key: project
      - key: team
        values: [infra, search]
```

| Field | Default | What it does |
|---|---|---|
| `allowed` | required | The tag keys that a request can have. `values` limits a key to those values. Without `values`, the key can have any valid value. |
| `from_header` | `false` | Read the `x-cost-tags` header. If `false`, the proxy does not read the header and sends it upstream without change. If `true`, the proxy removes the header before it sends the request upstream. |
| `max_tags` | `8` | The maximum number of tags on one request, 1 to 32. Key-metadata tags fill this limit first. |
| `max_value_bytes` | `64` | The maximum length of a tag value in bytes, 1 to 256. |

A tag key has 1 to 64 bytes of lowercase letters, digits, `_`, `.` and `-`,
and starts with a letter. A tag value has ASCII letters, digits, and
`_ . : / @ + -` only. These rules prevent injection into a CSV export or a log
line.

## Tags from JWT claims

A JWT caller has no key metadata. To attribute its spend, map verified claims
to tags on the JWT provider:

```yaml
auth:
  chargeback_tags:
    allowed:
      - key: team
        values: [infra, search]
      - key: project
  jwt:
    - issuer: https://login.example.com/
      # audience, jwks, tenant and user as usual
      claim_tags:
        - { claim: department, tag: team }
        - { claim: cost_center, tag: project }
```

The proxy reads each `claim` from the token after it verifies the signature.
The claim value becomes the value of `tag`. The value then goes through the
same allow-list and limits as every other tag.

- `auth.chargeback_tags` must be set, and each `tag` must be in its
  `allowed` list. Otherwise the config does not load.
- A `tag` can occur only one time in one provider.
- The header cannot set a mapped tag, also when the claim is missing or the
  proxy drops its value.
- A claim that is not in the token is dropped as `claim_missing`. A claim that
  is not a string, or has a character that is not valid in a tag value, is
  dropped as `malformed`. The request is served.
- Only top-level claims are read.

## Set tags on a key

Set tags when you mint a key. `POST /keys` accepts an optional `tags` map:

```bash
curl -X POST http://$ADMIN_ADDR/keys \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -d '{"tenant":"acme","key_id":"search-ci","tags":{"team":"search"}}'
```

If you mint a key id again to rotate the key and do not send `tags`, the key
keeps its tags.

`PUT /keys/{id}/tags` replaces the tags of a key. An empty map removes them.

```bash
curl -X PUT http://$ADMIN_ADDR/keys/search-ci/tags \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -d '{"tags":{"team":"search","project":"ranking"}}'
```

| Status | Cause |
|---|---|
| `204` | The proxy stored the tags. Requests that authenticate after the change get them. |
| `400` | A tag key or value is not valid, there are more than 32 tags, or `tags` is missing. |
| `404` | The key does not exist. |
| `409` | The key is revoked, or the key is in the config file. Set the tags of a config-file key in `auth.keys[].tags`. |

Key metadata can hold tags that the allow-list does not accept. The proxy
drops them at request time and counts them.

`GET /keys` and `GET /keys/{id}/spend` show the tags of each key.

## What the proxy drops

The proxy drops each tag that fails a rule, and serves the request. It counts
each drop in `llmproxy_chargeback_tags_dropped_total` with a `reason` label:

| Reason | Cause |
|---|---|
| `not_allowed` | The key is not in `allowed`, or the value is not in its `values`. |
| `too_long` | The value is longer than `max_value_bytes`. |
| `over_count` | The request has more than `max_tags` accepted tags. |
| `malformed` | The header did not parse, and the proxy drops all of its tags. Or a mapped JWT claim is not a string of valid tag value characters. |
| `overridden` | The header set a tag key that key metadata or a JWT claim mapping also sets. |
| `claim_missing` | A mapped JWT claim is not in the token. |

A header is malformed if it has an item without `=`, an empty item, a key that
is not valid, a value with a character that is not valid, the same key two
times, more than 4096 bytes, or if the request has the header two times.

Tag keys and values are never metric labels. Only the six `reason` values
make series, so many different tag values cannot increase the number of
series.

## Read tags back

- **Billing ledger.** Each entry has the tags in `record.tags`. Entries that
  this release writes have `schema_version` `2`. See
  [Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/#fields-of-an-entry).
- **Request records.** A request record has a `tags` object. It is empty when
  the request has no tags.
- **Keys.** `GET /keys` and `GET /keys/{id}/spend` show the key-metadata tags.
  Claim tags are not stored. They show only on the request record and the
  ledger entry.

## Limitations

- Tags are attribution only. A tag has no budget and no limit.
- Only the allow-list decides which tags a request gets. A client cannot add a
  tag that is not in `allowed`.
- Claim tags are not stored on the key. They show only on the request record
  and the ledger entry.
- The proxy reads only top-level JWT claims, and only string values.
- Tag keys and values are never metric labels.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Upgrades and downgrades

A key with tags is stored with store row version 3. A build from before
chargeback tags refuses to load a store that has such a row. It does not read
the key without its tags. To downgrade, remove the tags from every key first
with `PUT /keys/{id}/tags` and `{"tags":{}}`.
