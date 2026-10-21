---
title: Vertex AI
description: Configure Google Vertex AI with a project, location, publisher, and an OAuth access token that you supply or that the proxy mints, and set the dialect on each model.
summary: The vertex provider block, the streamRawPredict path template, the
  three token sources, the mandatory model dialect, and token failure behavior.
lastUpdated: 2026-10-21
related:
  - providers/overview
  - providers/anthropic
  - providers/amazon-bedrock
  - configuration/models-and-routes
  - providers-and-routing/failover-and-aggregates
---

The `vertex` type sends requests to Google Vertex AI. The proxy builds the
Vertex URL path from the project, location, publisher, and model. It sends an
OAuth access token as a Bearer token. You supply the token, or the proxy mints
and refreshes it. One Vertex provider can host models with different wire
formats, so each `models` entry must state its `dialect`.

## At a glance

- **Auth:** `Authorization: Bearer <token>`. Choose one token source:
  `access_token`, `access_token_file`, or `oauth2_jwt_bearer`.
- **Dialect:** `openai` or `anthropic`, set on the `models` entry. The proxy
  never guesses it.
- **Fails closed or open:** a missing field or a missing dialect fails the load
  with the field path. At run time, a minted token that is not available fails
  closed. See [When no token is available](#when-no-token-is-available).

## Minimal example

This example uses a token that you supply.

```yaml title="llmproxy.yaml"
version: 0
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  vertex-us:
    type: vertex
    base_url: https://us-central1-aiplatform.googleapis.com
    project: my-project
    location: us-central1
    publisher: anthropic
    access_token: ${VERTEX_ACCESS_TOKEN}

routes: []
models:
  claude-sonnet:
    providers:
      - provider: vertex-us
        model: claude-sonnet-4-5@20250929
        dialect: anthropic
```

1. Get a token and check the file.

   ```bash
   export VERTEX_ACCESS_TOKEN="$(gcloud auth print-access-token)"
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
          "anthropic_version":"vertex-2023-10-16",
          "messages":[{"role":"user","content":"hi"}]}'
   ```

The `model` ID and the `anthropic_version` value are examples. Check them
against the Vertex documentation for your model. The proxy does not add or
change `anthropic_version`. The client must send the value that Vertex needs.

## What the proxy sends

The proxy replaces the whole request path. It keeps the query string.

```text
/v1/projects/<project>/locations/<location>/publishers/<publisher>/models/<model>:streamRawPredict
```

`<model>` is the mapped `model:` value if a `models` key matches the request
model. Otherwise it is the request model. The proxy percent-encodes it: the `@`
in `claude-sonnet-4-5@20250929` becomes `%40`. The suffix is always
`:streamRawPredict`, for streaming and non-streaming requests.

## Fields

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `type` | enum | none | yes: set `vertex` | |
| `base_url` | URI | none | yes | Regional host, no path. |
| `project` | string | none | yes | Google Cloud project ID. |
| `location` | string | none | yes | Google Cloud location. |
| `publisher` | string | none | yes | For example `anthropic` or `google`. |
| `access_token` | string | none | one of three | OAuth access token. The proxy applies it as is and never refreshes it. |
| `access_token_file` | string | none | one of three | File with the token. |
| `oauth2_jwt_bearer` | object | none | one of three | The proxy mints and refreshes the token. See [Mint the token in the proxy](#mint-the-token-in-the-proxy). |
| `extra_headers`, `ca_file`, `connect_timeout`, `protocol` | | empty, system roots, `5s`, `http1` | no | Common fields. See the [provider overview](/docs/llm-proxy/providers/overview/). |

Set exactly one of `access_token`, `access_token_file`, and
`oauth2_jwt_bearer`. The load fails if you set `api_key`, `region`, or an AWS
field. The load also fails if you set the Vertex fields on another type. The
`tenant_credentials` option is not available for `vertex`:

```text
invalid value at `providers.<name>.tenant_credentials`: not supported for `vertex` providers: they authenticate with OAuth2 or SigV4, not a header API key, so their cluster cannot carry a tenant credential
```

## Token from a file

```yaml title="Fragment: token from a file"
providers:
  vertex-us:
    type: vertex
    base_url: https://us-central1-aiplatform.googleapis.com
    project: my-project
    location: us-central1
    publisher: anthropic
    access_token_file: /run/secrets/vertex_token
```

The proxy reads the file at startup and again on each `SIGHUP` reload. It
prints this warning on stderr:

```text
warning: `providers.vertex-us.access_token_file`: the credential file is read at startup and again on each SIGHUP reload; to rotate it, replace the file and reload
```

Google access tokens expire, usually after one hour. Your platform must
refresh the file, and you must send `SIGHUP` to use the new token. Nothing
watches the file. To avoid this work, mint the token in the proxy.

## Mint the token in the proxy

With `oauth2_jwt_bearer`, the proxy signs an RS256 assertion with a service
account key. It exchanges the assertion at the token endpoint (the OAuth2
JWT-bearer grant, RFC 7523). It mints the next token before the current one
expires.

```yaml title="Fragment: minted token"
providers:
  vertex-us:
    type: vertex
    base_url: https://us-central1-aiplatform.googleapis.com
    project: my-project
    location: us-central1
    publisher: anthropic
    oauth2_jwt_bearer:
      token_url: https://oauth2.googleapis.com/token
      issuer: llm-proxy@my-project.iam.gserviceaccount.com
      key_id: 0123456789abcdef0123456789abcdef01234567
      private_key_file: /etc/llm-proxy/vertex-sa.pem
      scopes:
        - https://www.googleapis.com/auth/cloud-platform
```

A Google service account key is a JSON file. Extract the PEM key and the two
identifiers from it:

```bash
jq -r .private_key    key.json > /etc/llm-proxy/vertex-sa.pem
jq -r .client_email   key.json   # use as issuer
jq -r .private_key_id key.json   # use as key_id
```

The token URL and the scope above are the Google values for Vertex AI. The
proxy holds no provider values of its own. The file
`examples/llmproxy-vertex-oauth2.yaml` has a complete example.

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `token_url` | string | none | yes | Token endpoint. It must use `https`. Plain `http` is accepted only to a loopback host. |
| `issuer` | string | none | yes | JWT `iss`, for example the email address of the service account. |
| `private_key_file` | string | none | yes | RSA private key in PKCS#8 PEM format (`BEGIN PRIVATE KEY`). The proxy reads and checks it at every load. A bad key is a load error. |
| `scopes` | list of strings | none | yes | At least one scope. The proxy joins them with spaces into the JWT `scope` claim. A scope cannot contain a space. |
| `subject` | string | none | no | JWT `sub`, when the grant acts for another principal. |
| `key_id` | string | none | no | JWT header `kid`. |
| `audience` | string | `token_url` | no | JWT `aud`. |
| `assertion_lifetime` | duration | `1h` | no | `exp - iat` of each assertion. Whole seconds from `1s` to `24h`. |
| `refresh_before` | duration | `5m` | no | The proxy mints the next token this long before the current one expires. Whole seconds from `1s` to `24h`. |
| `timeout` | duration | `10s` | no | Limit for one token request, connection setup included. Whole seconds from `1s` to `24h`. |
| `ca_file` | string | system roots | no | PEM bundle that verifies an `https` token endpoint. Valid only with an `https` `token_url`. |

To rotate the service account key, replace the key file and send `SIGHUP`. The
proxy then mints with the new key.

### When no token is available

If the proxy has no unexpired token, it does not send the request to Vertex.

- If the model has a next provider, the request moves to it. The metric
  `llmproxy_provider_credential_requests_total` counts it with
  `outcome=unavailable_failover`.
- If there is no next provider, the client gets a local `503` with the body
  `provider token unavailable`. The metric counts it with
  `outcome=unavailable`.

## The dialect is mandatory

A `routes` entry cannot carry `dialect`. The shorthand form of a `models` entry
cannot carry it either. This config fails the load:

```yaml title="Fragment: fails the load"
models:
  claude-sonnet:
    providers:
      - vertex-us/claude-sonnet-4-5@20250929
```

```text
invalid value at `models.claude-sonnet.providers[0]`: `vertex` providers serve more than one wire format under one type (e.g. Vertex hosts Anthropic-, Google-, and OpenAI-shaped models), so `dialect` cannot be derived here; the shorthand string form cannot carry `dialect` -- use the object form ({ provider, model, dialect }) and set it explicitly
```

Use the object form, as in the minimal example. The object form with no
`dialect` fails with the path `models.<name>.providers[0].dialect`. A `routes`
entry can name a Vertex provider only if a `models` entry names it with an
explicit dialect. The `dialect` also selects the response parser for token
counts. A wrong value gives wrong usage numbers, so check it.

## Failover

A Vertex provider can sit in a chain with any provider of the same dialect. A
Vertex provider with `dialect: anthropic` pairs with `anthropic` providers and
with Bedrock entries that set `dialect: anthropic`:

```yaml title="Fragment: two Vertex regions"
providers:
  vertex-us:
    type: vertex
    base_url: https://us-central1-aiplatform.googleapis.com
    project: my-project
    location: us-central1
    publisher: anthropic
    access_token: ${VERTEX_US_TOKEN}
  vertex-eu:
    type: vertex
    base_url: https://europe-west1-aiplatform.googleapis.com
    project: my-project
    location: europe-west1
    publisher: anthropic
    access_token: ${VERTEX_EU_TOKEN}

models:
  claude-sonnet:
    providers:
      - { provider: vertex-us, model: "claude-sonnet-4-5@20250929", dialect: anthropic }
      - { provider: vertex-eu, model: "claude-sonnet-4-5@20250929", dialect: anthropic }
```

Each member builds its own path and sends its own token. A fallback never gets
the token of the primary. The proxy tries the second entry after a connection
failure, `429`, `500`, `502`, or `503`.

## Limitations

- A token from `access_token` or `access_token_file` is not refreshed. Use
  `oauth2_jwt_bearer` for a token that the proxy refreshes.
- The proxy does not read Google application default credentials or the
  metadata server.
- Only the `openai` and `anthropic` dialects exist. The proxy has no
  Gemini-native (`generateContent`) support. The path suffix is always
  `:streamRawPredict`.
- All models of one provider share one `publisher`.
- `base_url` cannot carry a path.
- See [Limitations](/docs/llm-proxy/help/limitations/).
