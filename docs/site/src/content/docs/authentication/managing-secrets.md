---
title: Manage configured virtual keys
description: "Create a virtual key in the config file, grant it model access, verify it, revoke it, and rotate the HMAC secret."
summary: The lifecycle of a virtual key listed in `auth.keys`. Generate the
  key with `--mode keygen`, install its digest, restart, grant the tenant a
  model policy, verify the request, revoke the key, and rotate the HMAC
  secret. Keys minted through the admin API are covered on the Virtual keys
  page.
lastUpdated: 2026-10-18
related:
  - authentication/virtual-keys
  - configuration/configuration-file
  - operations/config-reload
  - reference/cli
---

# Manage configured virtual keys

This page is the lifecycle of a virtual key that you list in the config file:
generate it, install its digest, grant its tenant access to models, verify
it, revoke it, and rotate the HMAC secret that keys every digest.

**Every change to `auth.keys` or the HMAC secret takes a restart.** A
`SIGHUP` reload that changes them is refused, and the proxy keeps the running
keys and secret (see
[Reload configuration](../../operations/config-reload/#what-a-reload-applies)). Keys
can also be minted and revoked at runtime through the admin API, without a
restart; see
[Managing keys and tenants at runtime](../../authentication/virtual-keys/#managing-keys-and-tenants-at-runtime).

## Before you start

- A config file with an `auth:` block and an `admin:` address. The starter
  config from `llm-proxy init` has both.
- `LLMPROXY_ADMIN_TOKEN` set in the environment of the proxy process. You
  need it in step 5 to grant model access. With the variable unset, every
  admin write returns `403`.
- `curl`.

## The HMAC secret

Every digest in `auth.keys[]` is `hex(HMAC-SHA256(hmac_secret, <plaintext
key>))`. Set exactly one of:

- `auth.hmac_secret`: an inline value, normally `${LLMPROXY_AUTH_SECRET}`
  from the environment.
- `auth.hmac_secret_file`: a path to a file that holds the secret.

Setting both, or neither, is a load error at `auth`.

**The proxy trims trailing whitespace from a secret file, not from an inline
value.** `echo "s3cret" > secret.txt` adds a newline. Both
`llm-proxy --mode keygen --hmac-secret-file` and the running proxy remove it,
so the two agree. An inline `hmac_secret:` value or `$LLMPROXY_AUTH_SECRET` is
used exactly as given.

If you compute a digest by hand instead of with `--mode keygen`, use
`printf %s`, never a here-string. `<<<` adds a newline that changes the
digest:

```sh
printf %s "llmp_yourkey" | openssl dgst -sha256 -hmac "$LLMPROXY_AUTH_SECRET" -hex
```

## Step 1: Generate a key

Run this in the directory that holds the secret file:

```sh
llm-proxy --mode keygen --tenant acme --key-id alice-laptop --hmac-secret-file secret.txt
```

| Flag | Required | What it does |
|---|---|---|
| `--tenant <TENANT>` | yes | The tenant the key authenticates as. |
| `--key-id <ID>` | no (default `REPLACE_ME`) | Names the key in logs and in `auth.keys[].id`. |
| `--hmac-secret-file <PATH>` | this or `$LLMPROXY_AUTH_SECRET` | Computes the digest with the contents of this file. It takes precedence over the environment variable. |

The command prints a fragment like this (placeholders shown):

```text
Key (shown once -- store it now; it cannot be recovered from the config):

  llmp_<REPLACE-WITH-YOUR-GENERATED-KEY>

Add to your llmproxy.yaml:

  auth:
    keys:
      - id: alice-laptop
        tenant: acme
        digest: <REPLACE-WITH-YOUR-GENERATED-DIGEST-64-HEX-CHARS>
```

Copy the plaintext key now. The proxy keeps only the digest, and you cannot
get the key back from it. The key is `llmp_` followed by 32 random bytes,
base64url-encoded.

## Step 2: Install the digest

Add the printed `id`, `tenant`, and `digest` under `auth.keys`:

```yaml
auth:
  hmac_secret_file: secret.txt
  keys:
    - id: alice-laptop
      tenant: acme
      digest: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a
```

A duplicate `id`, a duplicate `digest`, or a digest that is not exactly 64
lowercase hex characters is a load error that names the field. Check the file:

```sh
llm-proxy --config llmproxy.yaml --mode validate
```

## Step 3: Restart the proxy

Stop the proxy and start it again with the same command. A `SIGHUP` reload
that adds the key is refused, and the log names `auth.keys`.

## Step 4: Know the starting policy

A valid key authenticates the caller. The tenant must also have a model
policy that permits the requested model. By default
(`auth.enforce.tenants_without_policy: deny`), a tenant with no stored policy
gets `403` for every model.

The starter config from `llm-proxy init` sets
`tenants_without_policy: allow`. With that setting, skip step 5. Remove the
setting before you give keys to other people.

## Step 5: Grant the tenant model access

Send the grant to the admin address, with the admin token:

```sh
curl -s -i -X PUT http://127.0.0.1:53422/tenants/acme/policy \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d '{"access":{"only":["gpt-4o-mini"]}}'
```

A `204 No Content` response means the policy is stored. The next request
uses it, with no reload. `{"access":"all"}` grants every model. Both lists
accept exact names or one trailing `*`; see
[Virtual keys](../../authentication/virtual-keys/#managing-keys-and-tenants-at-runtime)
for `deny` and per-key policies.

The policy lives in the auth store. With the default store, `in_memory`, a
restart deletes it, so grant it again after every restart, or set
`auth.store` to `persistent` or `shared`.

## Step 6: Verify

Send a request through the proxy listener with the plaintext key:

```sh
curl -s -i http://127.0.0.1:53421/v1/chat/completions \
  -H "authorization: Bearer llmp_<your key>" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

The proxy forwards an authorized request to the provider and returns the
response of the provider. If it refuses the request, the status tells you
which check failed:

| Status and body | Check that failed | What to do |
|---|---|---|
| `401` `unauthorized`, with `www-authenticate: Bearer` | Authentication. No `authorization: Bearer llmp_...` header, an unknown key, or a revoked key. All three look the same. | Check the key and the digest. The access log field `response_code_details` names the reason: `auth_no_credential`, `auth_unknown_key`, or `auth_revoked_key`. |
| `403` `forbidden` | Model access. The tenant has no policy, or its policy does not permit this model. A request with no `model` in its body also gets this. | Do step 5 for this tenant and model. |
| `503` `service unavailable` | Policy freshness. The proxy could not read the auth store for longer than `auth.max_policy_staleness` (default `4m`). | Fix the connection to the store. The proxy recovers at the next successful poll. |

## Revoke a key

Set `revoked: true` on the entry rather than deleting it, then restart:

```yaml
auth:
  keys:
    - id: alice-laptop
      tenant: acme
      digest: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a
      revoked: true
```

Until the restart, the key still authenticates. A revoked key gets the same
`401` as an unknown key, and the access log records `auth_revoked_key` for it.
A request that the proxy admitted before the restart is not affected.

To revoke a configured key without a restart, revoke its whole tenant:
`DELETE /tenants/{id}` on the admin API revokes every key of the tenant,
configured keys included. `DELETE /keys/{id}` revokes only keys minted
through the API; for a configured key it returns `404`. A revocation through
the admin API applies at once on the replica that receives it and within one
policy poll (48 to 60 seconds) on other replicas that share the store. With
the `in_memory` store, a restart loses it.

## Rotate the HMAC secret

**Rotating the secret invalidates every digest at once.** A digest is the HMAC
of the key under the secret, so no existing digest matches after the change.
This includes keys minted through the admin API.

You cannot carry a key across a rotation. Only the caller has the plaintext,
and you need it to compute the new digest. Treat a rotation as issuing new
keys to every caller:

1. Write the new secret to the secret file, or set the new
   `$LLMPROXY_AUTH_SECRET`.
2. Run `--mode keygen` for each key with the new secret.
3. Replace each `digest` in `auth.keys`.
4. Restart the proxy.
5. Give the new plaintext keys to the callers. A caller that sends an old key
   gets `401`.

A `SIGHUP` after you change the secret is refused: the proxy logs
`SIGHUP: config reload refused` naming `auth.hmac_secret` and keeps serving
with the old secret and the old digests.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every request gets `401` with a key you believe is correct | The digest was computed with a different secret than the one the proxy loaded. A common cause is a trailing newline in an inline secret, or `hmac_secret_file` pointing at another file. | Regenerate with `--mode keygen --hmac-secret-file` against the file the proxy uses, then restart. |
| A new or changed key in `auth.keys`, or a new secret, has no effect | The proxy was reloaded with `SIGHUP`, not restarted, and refused the reload (`SIGHUP: config reload refused` in the log). | Restart the proxy. |
| `403` `forbidden` after a successful key setup | The tenant has no model policy. | Grant access (step 5). |
| `403` on every admin call | `LLMPROXY_ADMIN_TOKEN` is not set for the proxy, or the request sent another token. | Set the variable for the proxy process and send it as `authorization: Bearer`. |
| `--mode keygen requires --tenant <TENANT>` | `keygen` ran without `--tenant`. | Add `--tenant <name>`. |
| `no HMAC secret: pass --hmac-secret-file <PATH>, or set $LLMPROXY_AUTH_SECRET` | No secret source. | Supply one of the two. |
| `--hmac-secret-file <path>: file is empty or contains only whitespace (an empty secret would make every digest effectively unkeyed)` | The secret file has no usable content. | Write a real secret to the file. |
| Load error at `auth`: `set either hmac_secret or hmac_secret_file` (or `, not both`) | Zero, or both, of the two fields are set. | Set exactly one. |
| Load error at `auth.keys[N].digest`: `must be exactly 64 hex characters` / `must be lowercase hex` | A hand-typed or truncated digest. | Regenerate with `--mode keygen`, or use `printf %s`, not `<<<`, with `openssl`. |
