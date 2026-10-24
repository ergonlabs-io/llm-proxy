---
title: Amazon Bedrock
description: Configure Amazon Bedrock with a region and AWS access keys. The proxy signs each request with SigV4 and rewrites the path to /model/<id>/invoke.
summary: The bedrock provider block, SigV4 signing, the invoke path template,
  the mandatory model dialect, and the static-credential limitation.
lastUpdated: 2026-10-21
related:
  - providers/overview
  - providers/anthropic
  - providers/vertex-ai
  - configuration/models-and-routes
  - providers-and-routing/failover-and-aggregates
---

The `bedrock` type sends requests to the Amazon Bedrock runtime. The proxy
signs every attempt with AWS Signature Version 4 and replaces the request path
with the Bedrock `invoke` path. You supply the access keys. Each `models` entry
must state its `dialect`.

## At a glance

- **Auth:** SigV4 with the service name `bedrock`. The proxy signs the final
  request, after the body and the path are set.
- **Dialect:** `openai` or `anthropic`, set on the `models` entry. The proxy
  never guesses it.
- **Fails closed or open:** a missing field or a missing dialect fails the load
  with the field path. If the proxy cannot sign a request, it does not send the
  request to Bedrock. The request moves to the next provider, or the client
  gets a local `503` with the body `provider credential failure`.

## Minimal example

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  bedrock:
    type: bedrock
    base_url: https://bedrock-runtime.us-east-1.amazonaws.com
    region: us-east-1
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}

routes: []
models:
  claude-sonnet:
    providers:
      - provider: bedrock
        model: anthropic.claude-sonnet-4-5-20250929-v1:0
        dialect: anthropic
```

1. Set the keys and check the file.

   ```bash
   export AWS_ACCESS_KEY_ID=...
   export AWS_SECRET_ACCESS_KEY=...
   llm-proxy --config llmproxy.yaml --mode validate
   ```

2. Start the proxy in a second terminal.

   ```bash
   llm-proxy --config llmproxy.yaml
   ```

3. Send a request.

   ```bash
   curl --max-time 60 http://127.0.0.1:53421/v1/messages \
     -H 'content-type: application/json' \
     -d '{"model":"claude-sonnet","max_tokens":64,
          "anthropic_version":"bedrock-2023-05-31",
          "messages":[{"role":"user","content":"hi"}]}'
   ```

The Bedrock `model` ID and the `anthropic_version` value are examples. Check
them against the Bedrock documentation. The proxy does not add
`anthropic_version`. The proxy has no Converse API support. The client must send
the body that the Bedrock `InvokeModel` API expects for the model.

## What the proxy sends

The proxy replaces the whole request path and keeps the query string:

```text
/model/<model>/invoke
```

`<model>` is the mapped `model:` value if a `models` key matches the request
model. Otherwise it is the request model. The proxy percent-encodes it, so the
`:` in `...-v1:0` becomes `%3A`. The proxy never produces the
`invoke-with-response-stream` path. The proxy sets the SigV4 headers
`x-amz-date` and `x-amz-content-sha256`. With a session token, it also sets
`x-amz-security-token`.

## Fields

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `type` | enum | none | yes: set `bedrock` | |
| `base_url` | URI | none | yes | Regional runtime host, no path. |
| `region` | string | none | yes | AWS region used in the signature. |
| `access_key_id` | string | none | one of two | AWS access key ID. |
| `access_key_id_file` | string | none | one of two | File with the access key ID. |
| `secret_access_key` | string | none | one of two | AWS secret access key. |
| `secret_access_key_file` | string | none | one of two | File with the secret access key. |
| `session_token` | string | none | no | Token for temporary credentials. Not with `session_token_file`. |
| `session_token_file` | string | none | no | File with the session token. |
| `extra_headers`, `ca_file`, `connect_timeout`, `protocol` | | empty, system roots, `5s`, `http1` | no | Common fields. See the [provider overview](/docs/llm-proxy/providers/overview/). |

Set exactly one source for the access key ID and exactly one for the secret
access key. The load fails if you set `api_key` or a Vertex field. The load
also fails if you set the Bedrock fields on another type. The
`tenant_credentials` option is not available for `bedrock`. The
[field reference](/docs/llm-proxy/configuration/reference/) lists every field.

## Credentials from files

```yaml title="Fragment: temporary credentials from files"
providers:
  bedrock:
    type: bedrock
    base_url: https://bedrock-runtime.us-east-1.amazonaws.com
    region: us-east-1
    access_key_id_file: /run/secrets/aws_access_key_id
    secret_access_key_file: /run/secrets/aws_secret_access_key
    session_token_file: /run/secrets/aws_session_token
```

The proxy trims trailing whitespace. It reads each file at startup and again on
each `SIGHUP` reload. Each file prints a warning on stderr, for example:

```text
warning: `providers.bedrock.access_key_id_file`: the credential file is read at startup and again on each SIGHUP reload; to rotate it, replace the file and reload
```

Temporary STS credentials expire. Your platform must refresh the files, and you
must send `SIGHUP` to use them. Nothing watches the files.

## The dialect is mandatory

The shorthand form of a `models` entry cannot carry `dialect`, and a `routes`
entry cannot carry it either. The object form with no `dialect` fails the load
with this error:

```text
invalid value at `models.claude-sonnet.providers[0].dialect`: `bedrock` providers serve more than one wire format under one type (e.g. Vertex hosts Anthropic-, Google-, and OpenAI-shaped models), so `dialect` cannot be derived here and must be set explicitly
```

A `routes` entry can name a Bedrock provider only if a `models` entry already
names it with an explicit dialect. The `dialect` also selects the response
parser for token counts.

## Failover

A Bedrock provider with `dialect: anthropic` can fail over to, or from,
`anthropic` and `vertex` entries with the same dialect. See the Bedrock example
on the [Anthropic](/docs/llm-proxy/providers/anthropic/) page. Each member signs
or authenticates with its own credential. A fallback never gets the AWS keys
unless it is a Bedrock provider with those keys.

## Limitations

- Credentials are static values from the configuration. The proxy does not read
  the AWS credential chain, instance roles, or web identity tokens.
- The path is always `/model/<model>/invoke`. The proxy does not support the
  Converse API or the response-stream path.
- Only the `openai` and `anthropic` dialects exist.
- `base_url` cannot carry a path.
- See [Limitations](/docs/llm-proxy/help/limitations/).
